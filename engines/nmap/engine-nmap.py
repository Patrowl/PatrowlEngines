#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import hashlib
import json
import optparse
import threading
import time
from collections import defaultdict
from shlex import split
from urllib.parse import urlparse
from copy import deepcopy
from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import banner

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = os.environ.get("DEBUG", "").lower() in ["true", "1", "yes", "y", "on"]
APP_MAXSCANS = int(os.environ.get("APP_MAXSCANS", 5))

APP_HOST = "0.0.0.0"
APP_PORT = 5001
APP_ENGINE_NAME = "nmap"
APP_SCAN_TIMEOUT_DEFAULT = int(os.environ.get("APP_SCAN_TIMEOUT_DEFAULT", 7200))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]

engine = PatrowlEngine(
    app=app, base_dir=BASE_DIR, name=APP_ENGINE_NAME, max_scans=APP_MAXSCANS
)
this.engine = engine


# Route actions
@app.route("/")
def default():
    """Handle default route."""
    return engine.default()


@app.route("/engines/nmap/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/nmap/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/nmap/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/nmap/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/nmap/clean")
def clean():
    """Clean all scans."""
    reloadconfig()
    return engine.clean()


@app.route("/engines/nmap/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    if scan_id not in engine.scans.keys():
        return (
            jsonify(
                {
                    "status": "error",
                    "reason": f"Error 1002: scan_id '{scan_id}' not found",
                }
            ),
            503,
        )
    return engine.clean_scan(scan_id)


def _engine_is_busy():
    """Returns if engine is busy scanning."""
    return engine._engine_is_busy()


@app.route("/engines/nmap/status")
def status():
    """Get status on engine and all scans."""
    return engine.get_status()


@app.route("/engines/nuclei/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    if scan_id not in engine.scans.keys():
        return (
            jsonify(
                {
                    "status": "error",
                    "reason": f"Error 1002: scan_id '{scan_id}' not found",
                }
            ),
            503,
        )
    return engine.getreport(scan_id)


def loadconfig():
    """Load configuration from local file."""
    res = {"page": "loadconfig"}
    conf_file = f"{BASE_DIR}/nmap.json"
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
    else:
        engine.scanner["status"] = "ERROR"
        return {"status": "ERROR", "reason": "config file not found."}

    if not os.path.isfile(engine.scanner["path"]):
        engine.scanner["status"] = "ERROR"
        return {"status": "ERROR", "reason": "path to nmap binary not found."}

    version_filename = f"{BASE_DIR}/VERSION"
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        engine.scanner["version"] = version_file.read().rstrip("\n")
        version_file.close()

    engine.scanner["status"] = "READY"
    res.update(
        {
            "status": "success",
            "message": "Config file loaded.",
            "config": engine.scanner,
        }
    )
    return res


@app.route("/engines/nmap/reloadconfig")
def reloadconfig():
    """Reload configuration route."""
    res = {"page": "reloadconfig"}
    loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    return engine.page_not_found()


@app.route("/engines/nmap/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/nmap/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.status_scan(scan_id)


# Stop all scans
@app.route("/engines/nmap/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop_scan()


@app.route("/engines/nmap/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    if scan_id not in engine.scans.keys():
        return (
            jsonify(
                {
                    "status": "error",
                    "reason": f"Error 1002: scan_id '{scan_id}' not found",
                }
            ),
            503,
        )
    return engine.stop_scan(scan_id)


##########################
@app.route("/engines/nmap/startscan", methods=["POST"])
def start():
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if _engine_is_busy() is True:
        res.update(
            {
                "status": "error",
                "reason": f"Scan refused: max concurrent active scans reached ({APP_MAXSCANS})",
            }
        )
        return jsonify(res), 503

    # update scanner status
    status()

    if engine.scanner["status"] != "READY":
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": "scanner not ready",
                    "status": engine.scanner["status"],
                },
            }
        )
        return jsonify(res), 503

    # Load scan parameters
    data = json.loads(request.data.decode("UTF-8"))
    if "assets" not in data.keys():
        res.update(
            {
                "status": "refused",
                "details": {"reason": "arg error, something is missing ('assets' ?)"},
            }
        )
        return jsonify(res), 500

    scan_id = str(data["scan_id"])
    if data["scan_id"] in engine.scans.keys():
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": f"scan '{data['scan_id']}' already launched",
                },
            }
        )
        return jsonify(res), 503

    options = {}
    if isinstance(data["options"], str):
        options = json.loads(data["options"])

    scan = {
        "assets": data["assets"],
        "threads": {},
        "proc": None,
        "position": data.get("position", 0),
        "root_scan_id": data.get("root_scan_id", 0),
        "options": options,
        "scan_id": scan_id,
        "status": "STARTED",
        "issues_available": False,
        "started_at": int(time.time() * 1000),
        "nb_findings": 0,
    }
    engine.scans.update({scan_id: scan})

    app.logger.debug("Launching thread for asset list")
    th = threading.Thread(
        target=_scan_thread,
        kwargs={"scan_id": scan_id, "thread_id": 0},
    )
    th.start()
    # engine.scans[scan_id]["threads"].append(th)

    res.update({"status": "accepted", "details": {"scan_id": scan["scan_id"]}})
    return jsonify(res)


def _scan_thread(scan_id, thread_id):
    hosts = []

    for asset in engine.scans[scan_id]["assets"]:
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            return jsonify(
                {
                    "status": "refused",
                    "details": {
                        "reason": f"datatype '{asset['datatype']}' not supported for the asset {asset['value']}."
                    },
                }
            )
        else:
            # extract the net location from urls if needed
            if asset["datatype"] == "url":
                hosts.append(
                    "{uri.netloc}".format(uri=urlparse(asset["value"])).strip()
                )
            else:
                hosts.append(asset["value"].strip())

    # ensure no duplicates
    hosts = list(set(hosts))

    # write hosts in a file (cleaner and doesn't break with shell arguments limit (for thousands of hosts)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nmap_hosts_{scan_id}.tmp"
    with open(hosts_filename, "w") as hosts_file:
        for item in hosts:
            hosts_file.write("%s\n" % item)
            app.logger.debug("asset: %s", item)

    # Sanitize args :
    options = engine.scans[scan_id]["options"]

    ports = None
    if "ports" in options:
        ports = ",".join(options["ports"])
    # del engine.scans[scan_id]['options']['ports']

    app.logger.debug("options: %s", options)

    log_path = f"{BASE_DIR}/logs/{scan_id}.error"

    cmd = f"{engine.scanner['path']} -vvv -oX {BASE_DIR}/results/nmap_{scan_id}.xml"

    # Check options
    for opt_key in options.keys():
        if (
            opt_key in engine.scanner["options"]
            and options.get(opt_key)
            and opt_key
            not in [
                "ports",
                "script",
                "top_ports",
                "script_args",
                "script_output_fields",
                "host_file_path",
            ]
        ):
            cmd += " {}".format(engine.scanner["options"][opt_key]["value"])
        if (
            opt_key == "ports" and ports is not None
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " -p{}".format(ports)
        if (
            opt_key == "top_ports"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --top-ports {}".format(options.get(opt_key))
        if opt_key == "script" and options.get(opt_key).endswith(
            ".nse"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script {}".format(options.get(opt_key))
        if (
            opt_key == "script_args"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script-args {}".format(options.get(opt_key))
        if (
            opt_key == "host_file_path"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            if os.path.isfile(options.get(opt_key)):
                with open(options.get(opt_key), "r") as f:
                    with open(hosts_filename, "a") as hosts_file:
                        for line in f:
                            hosts_file.write(line)
        if (
            opt_key == "min-rate"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --min-rate {}".format(options.get(opt_key))
        if (
            opt_key == "max-rtt-timeout"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --max-rtt-timeout {}".format(options.get(opt_key))
        if (
            opt_key == "max-parallelism"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --max-parallelism {}".format(options.get(opt_key))
        if (
            opt_key == "min-hostgroup"
        ):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --min-hostgroup {}".format(options.get(opt_key))
        if opt_key == "timing-template":
            cmd += " -T{}".format(options.get(opt_key))

    cmd += " -iL " + hosts_filename

    # Optimization trial for online scans
    # cmd += " -PE --osscan-limit --max-rtt-timeout 100ms --max-parallelism 100 --min-hostgroup 100"
    app.logger.debug("cmd: %s", cmd)

    cmd_sec = split(cmd)

    engine.scans[scan_id]["proc_cmd"] = "not set!!"
    with open(log_path, "w"):
        proc = subprocess.Popen(
            cmd_sec,
            shell=False,
            # stdout=open("/dev/null", "w"), stderr=stderr
            stdout=open("/dev/null", "w"),
            stderr=open("/dev/null", "w"),
        )
        engine.scans[scan_id]["proc"] = proc
        thread_info = {
            "thread_id": thread_id,
            "proc": proc,
            "cmd": cmd,
            "thread": threading.current_thread(),
            "status": "RUNNING",
            "asset": engine.scans[scan_id]["assets"],
        }
        engine.scans[scan_id]["threads"].update({thread_id: thread_info})
        engine.scans[scan_id]["status"] = "SCANNING"
        engine.scans[scan_id]["proc_cmd"] = cmd

    app.logger.debug(
        f"#####   RUNNING 1 scan on thread {thread_id}, for scan {scan_id}, scans length is {len(engine.scans)}   #####"
    )
    print(
        f"#####   RUNNING 1 scan on thread {thread_id}, for scan {scan_id}, scans length is {len(engine.scans)}   #####"
    )
    # # Define max timeout
    # max_timeout = APP_SCAN_TIMEOUT_DEFAULT
    # timeout = time.time() + max_timeout

    # while time.time() < timeout:
    #     if (
    #         hasattr(proc, "pid")
    #         and psutil.pid_exists(proc.pid)
    #         and psutil.Process(proc.pid).status() in ["sleeping", "running"]
    #     ):
    #         # Scan is still in progress
    #         time.sleep(3)
    #         # print(f'scan {scan_id} still running...')
    #     else:
    #         # Scan is finished
    #         # print(f'scan {scan_id} is finished !')
    #         break

    # time.sleep(1)  # wait for creating report file (could be long)

    # # Check if the report is available (exists && scan finished)
    # report_filename = f"{BASE_DIR}/results/nmap_{scan_id}.xml"
    # if not os.path.exists(report_filename):
    #     # engine.scans[scan_id]["status"] = "FINISHED"  # ERROR ?
    #     # engine.scans[scan_id]["issues_available"] = True
    #     engine.scans[scan_id]["status"] = "ERROR"
    #     engine.scans[scan_id]["issues_available"] = False
    #     return False

    # try:
    #     issues, summary, raw_hosts = _parse_report(report_filename, scan_id)

    #     # Check if banner grabbing is requested
    #     if "banner" in options.keys() and options["banner"] in [
    #         True,
    #         1,
    #         "true",
    #         "1",
    #         "y",
    #         "yes",
    #         "on",
    #     ]:
    #         extra_issues = get_service_banner(scan_id, raw_hosts)
    #         issues.extend(extra_issues)

    #     engine.scans[scan_id]["issues"] = deepcopy(issues)
    # except Exception as e:
    #     app.logger.info(e)
    #     # traceback.print_exception(*sys.exc_info())
    #     engine.scans[scan_id]["status"] = "ERROR"
    #     engine.scans[scan_id]["issues_available"] = False
    # engine.scans[scan_id]["issues_available"] = True
    # engine.scans[scan_id]["status"] = "FINISHED"

    return True


def hash_text(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:6]


def get_service_banner(scan_id, raw_hosts):
    ts = int(time.time() * 1000)
    res = []

    for host in raw_hosts.keys():
        ports = raw_hosts[host]

        target = {
            "addr": [host],
            "addr_type": "ipv4",
        }
        for port in ports:
            port_banner = banner.grab_banner(host, int(port)).replace(
                "\u0000", ""
            )  # Fix #218
            if port_banner == "":
                continue

            hash_banner = hash_text(port_banner)

            res.append(
                deepcopy(
                    _add_issue(
                        scan_id=scan_id,
                        target=target,
                        ts=ts,
                        title=f"Service banner for {host}:{port} (HASH: {hash_banner})",
                        desc=f"Service banner:\n\n{port_banner}",
                        type="port_banner",
                        raw={"banner": port_banner, "host": host, "port": port},
                    )
                )
            )

    return res


def _add_issue(
    scan_id,
    target,
    ts,
    title,
    desc,
    type,
    severity="info",
    confidence="certain",
    vuln_refs={},
    links=[],
    tags=[],
    risk={},
    raw=[],
):
    engine.scans[scan_id]["nb_findings"] = engine.scans[scan_id]["nb_findings"] + 1
    issue = {
        "issue_id": engine.scans[scan_id]["nb_findings"],
        "severity": severity,
        "confidence": confidence,
        "target": target,
        "title": title,
        "description": desc,
        "raw": raw,
        "solution": "n/a",
        "type": type,
        "timestamp": ts,
        "metadata": {
            "vuln_refs": vuln_refs,
            "risk": risk,
            "links": links,
            "tags": tags,
        },
    }

    return issue


def _parse_report(filename, scan_id):
    """Parse the nmap report."""
    issues = []
    target = {}
    raw_hosts = {}

    try:
        tree = ET.parse(filename)
    except Exception:
        # No Element found in XML file
        return issues, raw_hosts

    if tree.find("taskbegin") is not None:
        ts = tree.find("taskbegin").get("time")
    else:
        ts = tree.getroot().get("start")

    unresolved_domains = set()
    for a in engine.scans[scan_id]["assets"]:
        if a["datatype"] == "domain":
            unresolved_domains.add(a["value"])
    down_ips = set()
    for a in engine.scans[scan_id]["assets"]:
        if a["datatype"] == "ip":
            down_ips.add(a["value"])

    for host in tree.findall("host"):
        addr_list = []
        addr_type = host.find("address").get("addrtype")

        has_hostnames = False
        # Find hostnames
        for hostnames in host.findall("hostnames"):
            for hostname in list(hostnames):
                # if hostname.get("type") in ["user", "PTR"]:
                if hostname.get("type") == "user":
                    has_hostnames = True
                    addr = hostname.get("name")
                    addr_list.append(hostname.get("name"))

        # Get IP address otherwise
        if not has_hostnames:
            addr = host.find("address").get("addr")
            addr_list.append(addr)

        # Check if it was extracted from URLs. If yes: add them
        for a in engine.scans[scan_id]["assets"]:
            if a["datatype"] == "url" and urlparse(a["value"]).netloc in addr_list:
                addr_list.append(a["value"])

        # Initialize the 'target' value
        target = {
            "addr": addr_list,
            "addr_type": addr_type,
        }

        if has_hostnames:
            for hostnames in host.findall("hostnames"):
                for hostname in list(hostnames):
                    if hostname.get("type") != "user":
                        continue
                    ip_address = str(host.find("address").get("addr"))
                    issues.append(
                        deepcopy(
                            _add_issue(
                                scan_id,
                                target,
                                ts,
                                "Host '{}' has ip: '{}'".format(
                                    hostname.get("name"),
                                    host.find("address").get("addr"),
                                ),
                                "The scan detected that the host {} has IP '{}'".format(
                                    hostname.get("name"),
                                    host.find("address").get("addr"),
                                ),
                                type="host_ip",
                                raw=ip_address,
                            )
                        )
                    )

                    addr_list.append(ip_address)
                    addr_list = list(set(addr_list))
                    target.update({"addr": addr_list})

        for a in addr_list:
            if a not in raw_hosts.keys():
                raw_hosts.update({a: []})

        # Add the addr_list to identified_assets (post exec: spot unresolved domains)
        unresolved_domains = unresolved_domains.difference(set(addr_list))
        # Add the addr_list to identified_assets (post exec: spot ips that are down. Not added to nmap xml if --open is used)
        down_ips = down_ips.difference(set(addr_list))

        # get OS information
        if host.find("os") is not None:
            osinfo = host.find("os").find("osmatch")
            if osinfo is not None:
                os_data = defaultdict(list)
                os_data["name"] = osinfo.get("name")
                os_data["accuracy"] = osinfo.get("accuracy")
                for osclass in osinfo.findall("osclass"):
                    os_cpe = osclass.find("cpe")
                    if os_cpe is not None:
                        os_data["cpe"].append(os_cpe.text)
                issues.append(
                    deepcopy(
                        _add_issue(
                            scan_id,
                            target,
                            ts,
                            "OS: {}".format(osinfo.get("name")),
                            "The scan detected that the host run in OS '{}' (accuracy={}%)".format(
                                osinfo.get("name"), osinfo.get("accuracy")
                            ),
                            type="host_osinfo",
                            raw=os_data,
                            confidence="undefined",
                        )
                    )
                )

        openports = False
        # get ports status - generate issues
        if host.find("ports") is not None:
            all_open_ports = []
            for port in host.find("ports"):
                if port.tag == "extraports":
                    continue
                proto = port.get("protocol")
                portid = port.get("portid")
                port_state = port.find("state").get("state")
                port_data = {
                    "protocol": proto,
                    "port_id": portid,
                    "port_state": port_state,
                }

                target.update(port_data)

                if port_state == "open":
                    for t in target["addr"]:
                        if portid not in raw_hosts[t]:
                            raw_hosts[t].append(portid)

                # get service information if available
                if port.find("service") is not None and port_state not in [
                    "filtered",
                    "closed",
                ]:
                    svc_name = port.find("service").get("name")
                    if svc_name == "tcpwrapped":  # Classic shit with WAF and Firewalls
                        continue
                    target.update({"service": svc_name})
                    port_data.update({"service": svc_name})

                    # Check if a CPE has been identified
                    cpe_info = ""
                    cpe_links = []
                    cpe_refs = {}
                    cpe_vectors = []
                    for cpe in port.find("service").findall("cpe"):
                        if cpe is not None:
                            cpe_vector = cpe.text
                            cpe_link = _get_cpe_link(cpe_vector)
                            cpe_info += f"\n The following CPE vector has been identified: {cpe_vector}"
                            cpe_refs = {"CPE": [cpe_vector]}
                            cpe_vectors.append(cpe_vector)
                            cpe_links.append(cpe_link)
                    if cpe_vectors:
                        cpe_refs = {"CPE": cpe_vectors}
                        port_data.update({"cpe": cpe_vectors})

                    # <service name="http" product="Pulse Secure VPN gateway http config" devicetype="security-misc" tunnel="ssl" method="probed" conf="10"/>
                    # Detection method
                    try:
                        detection_method = port.find("service").get("method")
                        port_data.update({"detection_method": detection_method})
                    except Exception:
                        pass

                    # Version
                    try:
                        svc_version = port.find("service").get("version")
                        port_data.update({"version": svc_version})
                    except Exception:
                        pass

                    # Extra info
                    try:
                        svc_extrainfo = port.find("service").get("extrainfo")
                        port_data.update({"extrainfo": svc_extrainfo})
                    except Exception:
                        pass

                    # SSL Tunnel
                    try:
                        svc_tunnel = port.find("service").get("tunnel")
                        port_data.update({"tunnel": svc_tunnel})
                    except Exception:
                        pass

                    # Product
                    try:
                        p = port.find("service").get("product")
                        product = f"\nProduct: {p}"
                        port_data.update({"product": p})
                    except Exception:
                        product = ""

                    script_output = ""

                    # Get Result from Port Script.
                    for port_script in port.findall("script"):
                        script_output += port_script.get("output") + "\n"
                    port_data.update({"script_output": script_output})
                    issues.append(
                        deepcopy(
                            _add_issue(
                                scan_id,
                                target,
                                ts,
                                "Service '{}' is running on port '{}/{}'".format(
                                    svc_name, proto, portid
                                ),
                                "The scan detected that the service '{}' is running on port '{}/{}'. {}\n{}".format(
                                    svc_name, proto, portid, cpe_info, product
                                ),
                                type="port_info",
                                raw=port_data,
                                links=cpe_links,
                                vuln_refs=cpe_refs,
                            )
                        )
                    )

                if port_state not in ["filtered", "closed"]:
                    openports = True
                    all_open_ports.append(portid)
                    issues.append(
                        deepcopy(
                            _add_issue(
                                scan_id,
                                target,
                                ts,
                                "Port '{}/{}' is {}".format(proto, portid, port_state),
                                "The scan detected that the port '{}/{}' was {}".format(
                                    proto, portid, port_state
                                ),
                                type="port_status",
                                raw=port_data,
                            )
                        )
                    )

            if (
                not openports
                and "ports" in engine.scans[scan_id]["options"].keys()
                and engine.scans[scan_id]["options"]["ports"][0] in ["-", "1-65535"]
            ):  # only if all ports were scanned you can add the finding
                issues.append(
                    deepcopy(
                        _add_issue(
                            scan_id,
                            target,
                            ts,
                            "All Ports are closed",
                            "The scan detected that all ports are closed or filtered",
                            type="port_status_closed",
                        )
                    )
                )

            # Prepare and create a finding with all open ports
            all_open_ports = list(set(all_open_ports))
            all_open_ports.sort()
            all_open_ports_str = ",".join([str(x) for x in all_open_ports])
            all_open_ports_hash = hash_text(all_open_ports_str)
            issues.append(
                deepcopy(
                    _add_issue(
                        scan_id,
                        target,
                        ts,
                        f"Host has '{len(all_open_ports)}' open port(s) (HASH: {all_open_ports_hash})",
                        f"The scan detected following open ports: \n{all_open_ports_str}",
                        type="open_ports",
                        raw=all_open_ports,
                    )
                )
            )

        # get host status
        status = host.find("status").get("state")
        if openports:  # There are open ports so it must be up
            issues.append(
                deepcopy(
                    _add_issue(
                        scan_id,
                        target,
                        ts,
                        "Host '{}' is up".format(addr),
                        "The scan detected that the host {} was up".format(addr),
                        type="host_availability",
                    )
                )
            )
        # elif status and status == "up" and "no_ping" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["no_ping"] == '0': #if no_ping (-Pn) is used all hosts are always up even if they are not
        elif (
            status and status == "up"
        ):  # if no_ping (-Pn) is used all hosts are always up even if they are not
            # if "no_ping" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["no_ping"] == '0':
            issues.append(
                deepcopy(
                    _add_issue(
                        scan_id,
                        target,
                        ts,
                        "Host '{}' is up".format(addr),
                        "The scan detected that the host {} was up".format(addr),
                        type="host_availability",
                    )
                )
            )
        if status and status == "down":
            issues.append(
                deepcopy(
                    _add_issue(
                        scan_id,
                        target,
                        ts,
                        "Host '{}' is down".format(addr),
                        "The scan detected that the host {} was down".format(addr),
                        type="host_availability",
                    )
                )
            )
        # else:
        #     res.append(deepcopy(_add_issue(scan_id, target, ts,
        #         "Host '{}' is down".format(addr),
        #         "The scan detected that the host {} was down (allegedly)".format(addr),
        #         type="host_availability")))

        # get script results - generate issues
        if host.find("hostscript") is not None:
            for script in host.find("hostscript"):
                script_output = script.get("output")
                issues.append(
                    deepcopy(
                        _add_issue(
                            scan_id,
                            target,
                            ts,
                            "Script '{}' has given results".format(script.get("id")),
                            "The script '{}' revealed following information: \n{}".format(
                                script.get("id"), script_output
                            ),
                            type="host_script",
                        )
                    )
                )

                if "script_output_fields" in engine.scans[scan_id]["options"].keys():
                    for elem in script.findall("elem"):
                        if (
                            elem.get("key")
                            in engine.scans[scan_id]["options"]["script_output_fields"]
                        ):
                            issues.append(
                                deepcopy(
                                    _add_issue(
                                        scan_id,
                                        target,
                                        ts,
                                        "Script results '{}/{}' set to '{}'".format(
                                            script.get("id"), elem.get("key"), elem.text
                                        ),
                                        "The script '{}' revealed following information: \n'{}' was identified to '{}'".format(
                                            script.get("id"), elem.get("key"), elem.text
                                        ),
                                        type="host_script_advanced",
                                    )
                                )
                            )

    for unresolved_domain in unresolved_domains:
        target = {
            "addr": [unresolved_domain],
            "addr_type": "tcp",
        }
        issues.append(
            deepcopy(
                _add_issue(
                    scan_id,
                    target,
                    ts,
                    "Failed to resolve '{}'".format(unresolved_domain),
                    "The asset '{}' was not resolved by the engine.".format(
                        unresolved_domain
                    ),
                    type="nmap_error_unresolved",
                    severity="low",
                )
            )
        )
    if (
        "ports" in engine.scans[scan_id]["options"].keys()
        and engine.scans[scan_id]["options"]["ports"][0] in ["-", "1-65535"]
    ) or (
        "fast_scan" in engine.scans[scan_id]["options"].keys()
        and engine.scans[scan_id]["options"]["fast_scan"]
    ):
        for down_ip in down_ips:
            target = {
                "addr": [down_ip],
                "addr_type": "tcp",
            }
            issues.append(
                deepcopy(
                    _add_issue(
                        scan_id,
                        target,
                        ts,
                        "Host '{}' is down".format(down_ip),
                        "The scan detected that the host {} was down".format(down_ip),
                        type="host_availability",
                        severity="low",
                    )
                )
            )

    summary = {
        "nb_issues": len(issues),
        "nb_info": 0,
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "nb_critical": 0,
        "engine_name": "nmap",
    }
    return issues, summary, raw_hosts


def _get_cpe_link(cpe):
    return f"https://nvd.nist.gov/vuln/search/results?adv_search=true&cpe={cpe}"


# custom functions for Vulners issues
def _get_vulners_findings(findings):
    max_cvss = 0.0
    cve_list = []
    cve_links = []
    cpe_info = ""
    for line in findings.splitlines():
        cols = line.split("\t\t", 2)
        vulners_cve = cols[0].strip()
        if vulners_cve.startswith("cpe"):
            cpe_info = line.strip()
        if vulners_cve.startswith("CVE-"):
            vulners_cvss = float(cols[1])
            if vulners_cvss > max_cvss:
                max_cvss = vulners_cvss
            cve_list.append(vulners_cve)
            cve_links.append(cols[2].strip())
    return float(max_cvss), sorted(cve_list), sorted(cve_links), cpe_info


@app.route("/engines/nmap/getfindings/<scan_id>")
def getfindings(scan_id):
    """Get findings from engine."""
    res = {"page": "getfindings", "scan_id": scan_id}
    if scan_id not in engine.scans.keys():
        raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

    # check if the scan is finished (thread as well)
    status_res = engine.status_scan(scan_id)
    if engine.scans[scan_id]["status"] != "FINISHED":
        raise PatrowlEngineExceptions(
            1003,
            "scan_id '{}' not finished (status={})".format(
                scan_id, status_res["status"]
            ),
        )

    issues = []
    summary = {}
    scan = {"scan_id": scan_id}

    # check if the report is available (exists && scan finished)
    report_filename = f"{BASE_DIR}/results/nmap_{scan_id}.xml"
    if not os.path.exists(report_filename):
        res.update({"status": "error", "reason": "Report file not available"})
        return jsonify(res)

    issues, _, raw_hosts = _parse_report(report_filename, scan_id)

    # Check if banner grabbing is requested
    options = engine.scans[scan_id]["options"]
    if "banner" in options and options["banner"] in [
        True,
        1,
        "true",
        "1",
        "y",
        "yes",
        "on",
    ]:
        extra_issues = get_service_banner(scan_id, raw_hosts)
        issues.extend(extra_issues)

    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for issue in issues:
        nb_vulns[issue["severity"]] += 1

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "nmap",
        "engine_version": engine.scanner["version"],
    }

    # Store the findings in a file
    with open(f"{BASE_DIR}/results/nmap_{scan_id}.json", "w") as report_file:
        json.dump(
            {"scan": scan, "summary": summary, "issues": issues},
            report_file,
            default=_json_serial,
        )

    # Delete the tmp hosts file (used with -iL argument upon launching nmap)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nmap_hosts_{scan_id}.tmp"
    if os.path.exists(hosts_filename):
        os.remove(hosts_filename)

    # remove the scan from the active scan list
    # engine.clean_scan(scan_id)

    res.update({"summary": summary, "issues": issues, "status": "success"})
    return jsonify(res)


with app.app_context():
    """First function called."""
    # if os.getuid() != 0: #run with root because of docker env vars scope
    #    app.logger.error("Start the NMAP engine using root privileges !")
    #        sys.exit(-1)
    if not os.path.exists(f"{BASE_DIR}/results"):
        os.makedirs(f"{BASE_DIR}/results")
    if not os.path.exists(f"{BASE_DIR}/tmp"):
        os.makedirs(f"{BASE_DIR}/tmp")
    loadconfig()


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option(
        "-H",
        "--host",
        help="Hostname of the Flask app [default %s]" % APP_HOST,
        default=APP_HOST,
    )
    parser.add_option(
        "-P",
        "--port",
        help="Port for the Flask app [default %s]" % APP_PORT,
        default=APP_PORT,
    )
    parser.add_option(
        "-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP
    )

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
