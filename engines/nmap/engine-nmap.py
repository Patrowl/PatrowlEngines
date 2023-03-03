#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import psutil
import json
import optparse
import threading
import urllib
import time
import datetime
from collections import defaultdict
from shlex import split
from urllib.parse import urlparse
from copy import deepcopy
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
import xml.etree.ElementTree as ET
import banner

app = Flask(__name__)
APP_DEBUG = os.environ.get('DEBUG', '').lower() in ['true', '1', 'yes', 'y', 'on']
APP_HOST = "0.0.0.0"
APP_PORT = 5001
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 5))
APP_SCAN_TIMEOUT_DEFAULT = int(os.environ.get('APP_SCAN_TIMEOUT_DEFAULT', 7200))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scan_id = 1
this.scans = {}


# Generic functions
def _json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


# Route actions
@app.route('/')
def default():
    """Handle default route."""
    return redirect(url_for('index'))


@app.route('/engines/nmap/')
def index():
    """Handle index route."""
    return jsonify({"page": "index"})


def loadconfig():
    """Load configuration from local file."""
    conf_file = f"{BASE_DIR}/nmap.json"
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
    else:
        this.scanner['status'] = "ERROR"
        return {"status": "ERROR", "reason": "config file not found."}
    if not os.path.isfile(this.scanner['path']):
        this.scanner['status'] = "ERROR"
        return {"status": "ERROR", "reason": "path to nmap binary not found."}

    version_filename = f"{BASE_DIR}/VERSION"
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        this.scanner["version"] = version_file.read().rstrip('\n')
        version_file.close()


@app.route('/engines/nmap/reloadconfig')
def reloadconfig():
    """Reload configuration route."""
    res = {"page": "reloadconfig"}
    loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/nmap/startscan', methods=['POST'])
def start():
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) >= APP_MAXSCANS + 1:
        res.update({
            "status": "error",
            "reason": f"Scan refused: max concurrent active scans reached ({APP_MAXSCANS})"
        })
        return jsonify(res), 503

    # update scanner status
    status()

    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": this.scanner['status']
            }})
        return jsonify(res), 503

    # Load scan parameters
    data = json.loads(request.data.decode("UTF-8"))
    if 'assets' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        return jsonify(res), 500

    scan_id = str(data['scan_id'])
    if data['scan_id'] in this.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": f"scan '{data['scan_id']}' already launched",
            }})
        return jsonify(res), 503

    if type(data['options']) == str:
        data['options'] = json.loads(data['options'])

    scan = {
        'assets': data['assets'],
        'futures': [],
        'threads': [],
        'proc': None,
        'options': data['options'],
        'scan_id': scan_id,
        'status': "STARTED",
        'issues_available': False,
        'started_at': int(time.time() * 1000),
        'nb_findings': 0
    }

    this.scans.update({scan_id: scan})
    th = threading.Thread(target=_scan_thread, args=(scan_id,))
    th.start()
    this.scans[scan_id]['threads'].append(th)

    # th = this.pool.submit(_scan_thread, args=(scan_id,))
    # this.scans[scan_id]['futures'].append(th)

    res.update({
        "status": "accepted",
        "details": {"scan_id": scan['scan_id']}
    })

    return jsonify(res)


def _scan_thread(scan_id):
    hosts = []

    for asset in this.scans[scan_id]['assets']:
        if asset["datatype"] not in this.scanner["allowed_asset_types"]:
            return jsonify({
                "status": "refused",
                "details": {
                    "reason": f"datatype '{asset['datatype']}' not supported for the asset {asset['value']}."
                }})
        else:
            # extract the net location from urls if needed
            if asset["datatype"] == 'url':
                hosts.append("{uri.netloc}".format(uri=urlparse(asset["value"])).strip())
            else:
                hosts.append(asset["value"].strip())

    # ensure no duplicates
    hosts = list(set(hosts))

    # write hosts in a file (cleaner and doesn't break with shell arguments limit (for thousands of hosts)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nmap_hosts_{scan_id}.tmp"
    with open(hosts_filename, 'w') as hosts_file:
        for item in hosts:
            hosts_file.write("%s\n" % item)
            app.logger.debug('asset: %s', item)

    # Sanitize args :
    options = this.scans[scan_id]['options']

    ports = None
    if "ports" in options:
        ports = ",".join(options['ports'])
    # del this.scans[scan_id]['options']['ports']

    app.logger.debug('options: %s', options)

    log_path = f"{BASE_DIR}/logs/{scan_id}.error"

    cmd = f"{this.scanner['path']} -vvv -oX {BASE_DIR}/results/nmap_{scan_id}.xml"

    # Check options
    for opt_key in options.keys():
        if opt_key in this.scanner['options'] and options.get(opt_key) and opt_key not in ["ports", "script", "top_ports", "script_args", "script_output_fields", "host_file_path"]:
            cmd += " {}".format(this.scanner['options'][opt_key]['value'])
        if opt_key == "ports" and ports is not None:  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " -p{}".format(ports)
        if opt_key == "top_ports":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --top-ports {}".format(options.get(opt_key))
        if opt_key == "script" and options.get(opt_key).endswith('.nse'):  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script {}".format(options.get(opt_key))
        if opt_key == "script_args":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script-args {}".format(options.get(opt_key))
        if opt_key == "host_file_path":  # /!\ @todo / Security issue: Sanitize parameters here
            if os.path.isfile(options.get(opt_key)):
                with open(options.get(opt_key), 'r') as f:
                    with open(hosts_filename, 'a') as hosts_file:
                        for line in f:
                            hosts_file.write(line)
        if opt_key == "min-rate":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --min-rate {}".format(options.get(opt_key))
        if opt_key == "max-rtt-timeout":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --max-rtt-timeout {}".format(options.get(opt_key))
        if opt_key == "max-parallelism":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --max-parallelism {}".format(options.get(opt_key))
        if opt_key == "min-hostgroup":  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --min-hostgroup {}".format(options.get(opt_key))

    cmd += " -iL " + hosts_filename
    
    # Optimization trial for online scans
    # cmd += " -PE --osscan-limit --max-rtt-timeout 100ms --max-parallelism 100 --min-hostgroup 100"
    app.logger.debug('cmd: %s', cmd)

    cmd_sec = split(cmd)

    this.scans[scan_id]["proc_cmd"] = "not set!!"
    with open(log_path, "w") as stderr:
        this.scans[scan_id]["proc"] = subprocess.Popen(
            cmd_sec,
            shell=False,
            # stdout=open("/dev/null", "w"), stderr=stderr
            stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w")
        )
    this.scans[scan_id]["proc_cmd"] = cmd

    proc = this.scans[scan_id]["proc"]

    # Define max timeout
    max_timeout = APP_SCAN_TIMEOUT_DEFAULT
    timeout = time.time() + max_timeout

    # while time.time() < timeout:
    #     if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
    #         # Scan is still in progress
    #         time.sleep(3)
    #         # print(f'scan {scan_id} still running...')
    #     else:
    #         # Scan is finished
    #         # print(f'scan {scan_id} is finished !')
            
    #         # Check if the report is available (exists && scan finished)
    #         report_filename = f"{BASE_DIR}/results/nmap_{scan_id}.xml"
    #         if not os.path.exists(report_filename):
    #             return False

    #         issues, raw_hosts = _parse_report(report_filename, scan_id)

    #         # Check if banner grabbing is requested
    #         if "banner" in options.keys() and options["banner"] in [True, 1, "true", "1", "y", "yes", "on"]:
    #             extra_issues = get_service_banner(scan_id, raw_hosts)
    #             issues.extend(extra_issues)

    #         this.scans[scan_id]["issues"] = deepcopy(issues)
    #         this.scans[scan_id]["issues_available"] = True
    #         this.scans[scan_id]["status"] = "FINISHED"
    #         break

    # return True
    while time.time() < timeout:
        if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
            # Scan is still in progress
            time.sleep(3)
            # print(f'scan {scan_id} still running...')
        else:
            # Scan is finished
            # print(f'scan {scan_id} is finished !')
            break
            
    # Check if the report is available (exists && scan finished)
    report_filename = f"{BASE_DIR}/results/nmap_{scan_id}.xml"
    if not os.path.exists(report_filename):
        this.scans[scan_id]["status"] = "FINISHED"  # ERROR ?
        this.scans[scan_id]["issues_available"] = True
        return False

    try:
        issues, raw_hosts = _parse_report(report_filename, scan_id)

        # Check if banner grabbing is requested
        if "banner" in options.keys() and options["banner"] in [True, 1, "true", "1", "y", "yes", "on"]:
            extra_issues = get_service_banner(scan_id, raw_hosts)
            issues.extend(extra_issues)

        this.scans[scan_id]["issues"] = deepcopy(issues)
    except Exception:
        pass
    this.scans[scan_id]["issues_available"] = True
    this.scans[scan_id]["status"] = "FINISHED"

    return True


@app.route('/engines/nmap/clean')
def clean():
    res = {"page": "clean"}
    
    stop()
    this.scans.clear()
    loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/nmap/clean/<scan_id>')
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    stop_scan(scan_id)
    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/nmap/stopscans')
def stop():
    res = {"page": "stopscans"}

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})

    return jsonify(res)


@app.route('/engines/nmap/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "stopscan"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]
    if hasattr(proc, 'pid'):
        # his.proc.terminate()
        # proc.kill()
        # os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        if psutil.pid_exists(proc.pid):
            psutil.Process(proc.pid).terminate()
        res.update({
            "status": "TERMINATED",
            "details": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"],
                "scan_id": scan_id}
        })

    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    return jsonify(res)


@app.route('/engines/nmap/status/<scan_id>')
def scan_status(scan_id):
    res = {"page": "status", "status": "SCANNING"}
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res), 404

    if this.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res), 503

    proc = this.scans[scan_id]["proc"]
    if not hasattr(proc, "pid"):
        res.update({"status": "ERROR", "reason": "No PID found"})
        return jsonify(res), 503

    # if not psutil.pid_exists(proc.pid):
    if not psutil.pid_exists(proc.pid) and this.scans[scan_id]["issues_available"] is True:
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"
        # print(f"scan_status/scan '{scan_id}' is finished")

    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        res.update({
            "status": "SCANNING",
            "info": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"]}
        })
        # print(f"scan_status/scan '{scan_id}' is still SCANNING")
    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() == "zombie" and this.scans[scan_id]["issues_available"] is True:
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"
        psutil.Process(proc.pid).terminate()

    # print(scan_id, res['status'], psutil.pid_exists(proc.pid), hasattr(proc, "pid"), this.scans[scan_id]["issues_available"], psutil.Process(proc.pid).status())
    return jsonify(res)


@app.route('/engines/nmap/status')
def status():
    res = {"page": "status"}
    if not os.path.exists(f'{BASE_DIR}/nmap.json'):
        app.logger.error("nmap.json config file not found")
        this.scanner['status'] = "ERROR"

    if 'path' in this.scanner:
        if not os.path.isfile(this.scanner['path']):
            app.logger.error("NMAP engine not found (%s)", this.scanner['path'])
            this.scanner['status'] = "ERROR"
    #
    # if len(this.scans) >= APP_MAXSCANS:
    #     this.scanner['status'] = "BUSY"
    # else:
    #     this.scanner['status'] = "READY"

    this.scanner['status'] = "READY"
    if len(this.scans) >= APP_MAXSCANS:
        # count nb started
        nb_started = 0
        for scan in this.scans.keys():
            if this.scans[scan]['status'] == 'SCANNING':
                nb_started += 1
        if nb_started >= APP_MAXSCANS:
            this.scanner['status'] = "BUSY"

    res.update({"status": this.scanner['status']})

    # display info on the scanner
    res.update({"scanner": this.scanner})

    # display the status of scans performed
    scans = {}
    for scan in this.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": this.scans[scan]["status"],
            "options": this.scans[scan]["options"],
            "nb_findings": this.scans[scan]["nb_findings"],
        }})
    res.update({"scans": scans})
    return jsonify(res)


@app.route('/engines/nmap/info')
def info():
    scans = {}
    for scan in this.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": this.scans[scan]["status"],
            "options": this.scans[scan]["options"],
            "nb_findings": this.scans[scan]["nb_findings"],
        }})

    res = {
        "page": "info",
        "engine_config": this.scanner,
        "scans": scans
    }
    return jsonify(res)


def get_service_banner(scan_id, raw_hosts):
    ts = int(time.time() * 1000)
    res = []

    for host in raw_hosts.keys():
        ports = raw_hosts[host]

        target = {
            "addr": [host],
            "addr_type": 'ipv4',
        }
        for port in ports:
            port_banner = banner.grab_banner(host, int(port)).replace('\u0000', '')  # Fix #218
            if port_banner == '':
                continue

            res.append(deepcopy(_add_issue(
                scan_id=scan_id,
                target=target,
                ts=ts,
                title=f"Service banner for {host}:{port}",
                desc=f"Service banner:\n\n{port_banner}",
                type="port_banner",
                raw={
                    "banner": port_banner,
                    "host": host,
                    "port": port
                }
            )))

    return res


def _add_issue(scan_id, target, ts, title, desc, type, severity="info", confidence="certain", vuln_refs={}, links=[], tags=[], risk={}, raw=[]):
    this.scans[scan_id]["nb_findings"] = this.scans[scan_id]["nb_findings"] + 1
    issue = {
        "issue_id": this.scans[scan_id]["nb_findings"],
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
            "tags": tags
        }
    }

    return issue


def _parse_report(filename, scan_id):
    """Parse the nmap report."""
    res = []
    target = {}
    raw_hosts = {}
    try:
        tree = ET.parse(filename)
    except Exception:
        # No Element found in XML file
        return res, raw_hosts

    if tree.find("taskbegin") is not None:
        ts = tree.find("taskbegin").get("time")
    else:
        ts = tree.getroot().get("start")

    unresolved_domains = set()
    for a in this.scans[scan_id]["assets"]:
        if a["datatype"] == "domain":
            unresolved_domains.add(a["value"])
    down_ips = set()
    for a in this.scans[scan_id]["assets"]:
        if a["datatype"] == "ip":
            down_ips.add(a["value"])

    for host in tree.findall('host'):
        addr_list = []
        addr_type = host.find('address').get('addrtype')

        has_hostnames = False
        # Find hostnames
        for hostnames in host.findall('hostnames'):
            for hostname in list(hostnames):
                if hostname.get("type") in ["user", "PTR"]:
                    has_hostnames = True
                    addr = hostname.get("name")
                    addr_list.append(hostname.get("name"))

        # Get IP address otherwise
        if not has_hostnames:
            addr = host.find('address').get('addr')
            addr_list.append(addr)

        # Check if it was extracted from URLs. If yes: add them
        for a in this.scans[scan_id]["assets"]:
            if a["datatype"] == "url" and urlparse(a["value"]).netloc in addr_list:
                addr_list.append(a["value"])

        # Initialize the 'target' value
        target = {
            "addr": addr_list,
            "addr_type": addr_type,
        }

        if has_hostnames:
            for hostnames in host.findall('hostnames'):
                for hostname in list(hostnames):
                    ip_address = str(host.find('address').get('addr'))
                    res.append(deepcopy(_add_issue(scan_id, target, ts,
                        "Host '{}' has ip: '{}'".format(hostname.get('name'), host.find('address').get('addr')),
                        "The scan detected that the host {} has IP '{}'".format(hostname.get('name'), host.find('address').get('addr')),
                        type="host_ip", raw=ip_address)))

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
        if host.find('os') is not None:
            osinfo = host.find('os').find('osmatch')
            if osinfo is not None:
                os_data = defaultdict(list)
                os_data['name'] = osinfo.get('name')
                os_data['accuracy'] = osinfo.get('accuracy')
                for osclass in osinfo.findall('osclass'):
                    os_data['cpe'].append(osclass.find('cpe').text)
                res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "OS: {}".format(osinfo.get('name')),
                    "The scan detected that the host run in OS '{}' (accuracy={}%)"
                        .format(osinfo.get('name'), osinfo.get('accuracy')),
                    type="host_osinfo",
                    raw=os_data,
                    confidence="undefined")))

        openports = False
        # get ports status - generate issues
        if host.find('ports') is not None:
            for port in host.find('ports'):
                if port.tag == 'extraports':
                    continue
                proto = port.get('protocol')
                portid = port.get('portid')
                port_state = port.find('state').get('state')
                port_data = {
                    "protocol": proto,
                    "port_id": portid,
                    "port_state": port_state
                }

                target.update(port_data)

                if port_state == 'open':
                    for t in target["addr"]:
                        if portid not in raw_hosts[t]:
                            raw_hosts[t].append(portid)

                # get service information if available
                if port.find('service') is not None and port.find('state').get('state') not in ["filtered", "closed"]:
                    svc_name = port.find('service').get('name')
                    if svc_name == "tcpwrapped":  # Classic shit with WAF and Firewalls
                        continue
                    target.update({"service": svc_name})
                    port_data.update({"service": svc_name})

                    # Check if a CPE has been identified
                    cpe_info = ""
                    cpe_links = []
                    cpe_refs = {}
                    cpe_vectors = []
                    for cpe in port.find('service').findall("cpe"):
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
                        detection_method = port.find('service').get('method')
                        port_data.update({"detection_method": detection_method})
                    except Exception:
                        pass

                    # Version
                    try:
                        svc_version = port.find('service').get('version')
                        port_data.update({"version": svc_version})
                    except Exception:
                        pass

                    # Extra info
                    try:
                        svc_extrainfo = port.find('service').get('extrainfo')
                        port_data.update({"extrainfo": svc_extrainfo})
                    except Exception:
                        pass

                    # SSL Tunnel
                    try:
                        svc_tunnel = port.find('service').get('tunnel')
                        port_data.update({"tunnel": svc_tunnel})
                    except Exception:
                        pass

                    # Product
                    try:
                        p = port.find('service').get('product')
                        product = f"\nProduct: {p}"
                        port_data.update({"product": p})
                    except Exception:
                        product = ""

                    res.append(deepcopy(_add_issue(scan_id, target, ts,
                        "Service '{}' is running on port '{}/{}'".format(svc_name, proto, portid),
                        "The scan detected that the service '{}' is running on port '{}/{}'. {}\n{}"
                            .format(svc_name, proto, portid, cpe_info, product),
                        type="port_info",
                        raw=port_data,
                        links=cpe_links,
                        vuln_refs=cpe_refs)))

                if port_state not in ["filtered", "closed"]:
                    openports = True
                    res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "Port '{}/{}' is {}".format(proto, portid, port_state),
                    "The scan detected that the port '{}/{}' was {}".format(
                        proto, portid, port_state),
                    type="port_status", raw=port_data)))

                for port_script in port.findall('script'):
                    script_id = port_script.get('id')
                    script_output = port_script.get('output')
                    # Disable hash for some script_id
                    # if script_id in ["fingerprint-strings"]:
                    #     script_hash = "None"
                    # else:
                    #     script_hash = hashlib.sha1(str(script_output).encode('utf-8')).hexdigest()[:6]

                    if script_id == "vulners":
                        port_max_cvss, port_cve_list, port_cve_links, port_cpe = _get_vulners_findings(script_output)

                        port_severity = "info"
                        if port_max_cvss >= 7.5:
                            port_severity = "high"
                        elif port_max_cvss >= 5.0 and port_max_cvss < 7.5:
                            port_severity = "medium"
                        elif port_max_cvss >= 3.0 and port_max_cvss < 5.0:
                            port_severity = "low"

                        res.append(deepcopy(_add_issue(scan_id, target, ts,
                            "Nmap script '{}' detected findings on port {}/{}"
                                .format(script_id, proto, portid),
                            "The script '{}' detected following findings:\n{}"
                                .format(script_id, script_output),
                            severity=port_severity,
                            type="port_script",
                            tags=[script_id],
                            risk={"cvss_base_score": port_max_cvss},
                            vuln_refs={"CVE": port_cve_list, "CPE": port_cpe},
                            links=port_cve_links
                        )))
                    else:
                        res.append(deepcopy(_add_issue(scan_id, target, ts,
                            "Nmap script '{}' detected findings on port {}/{}"
                                .format(script_id, proto, portid),
                            "The script '{}' detected following findings:\n{}"
                                .format(script_id, script_output),
                            type="port_script",
                            tags=[script_id])))
            if not openports and "ports" in this.scans[scan_id]["options"].keys() and this.scans[scan_id]["options"]["ports"][0] in ["-", '1-65535']: #only if all ports were scanned you can add the finding
                res.append(deepcopy(_add_issue(scan_id, target, ts,
                "All Ports are closed",
                "The scan detected that all ports are closed or filtered",
                type="port_status_closed")))

        # get host status
        status = host.find('status').get('state')
        if openports:  # There are open ports so it must be up
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                                           "Host '{}' is up".format(addr),
                                           "The scan detected that the host {} was up".format(addr),
                                           type="host_availability")))
        # elif status and status == "up" and "no_ping" in this.scans[scan_id]["options"].keys() and this.scans[scan_id]["options"]["no_ping"] == '0': #if no_ping (-Pn) is used all hosts are always up even if they are not
        elif status and status == "up":  # if no_ping (-Pn) is used all hosts are always up even if they are not
            # if "no_ping" in this.scans[scan_id]["options"].keys() and this.scans[scan_id]["options"]["no_ping"] == '0':
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                "Host '{}' is up".format(addr),
                "The scan detected that the host {} was up".format(addr),
                type="host_availability")))
        if status and status == "down":
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                "Host '{}' is down".format(addr),
                "The scan detected that the host {} was down".format(addr),
                type="host_availability")))
        # else:
        #     res.append(deepcopy(_add_issue(scan_id, target, ts,
        #         "Host '{}' is down".format(addr),
        #         "The scan detected that the host {} was down (allegedly)".format(addr),
        #         type="host_availability")))

        # get script results - generate issues
        if host.find('hostscript') is not None:
            for script in host.find('hostscript'):
                script_output = script.get('output')
                res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "Script '{}' has given results".format(script.get('id')),
                    "The script '{}' revealed following information: \n{}"
                        .format(script.get('id'), script_output),
                    type="host_script")))

                if "script_output_fields" in this.scans[scan_id]["options"].keys():
                    for elem in script.findall("elem"):
                        if elem.get("key") in this.scans[scan_id]["options"]["script_output_fields"]:
                            res.append(deepcopy(_add_issue(scan_id, target, ts,
                                "Script results '{}/{}' set to '{}'"
                                    .format(script.get('id'), elem.get("key"), elem.text),
                                "The script '{}' revealed following information: \n'{}' was identified to '{}'"
                                    .format(script.get('id'), elem.get("key"), elem.text),
                                type="host_script_advanced")))

    for unresolved_domain in unresolved_domains:
        target = {
            "addr": [unresolved_domain],
            "addr_type": "tcp",
        }
        res.append(deepcopy(_add_issue(scan_id, target, ts,
            "Failed to resolve '{}'".format(unresolved_domain),
            "The asset '{}' was not resolved by the engine.".format(unresolved_domain),
            type="nmap_error_unresolved", severity="low")))
    if ("ports" in this.scans[scan_id]["options"].keys() and \
       this.scans[scan_id]["options"]["ports"][0] in ["-", '1-65535']) or \
       ("fast_scan" in this.scans[scan_id]["options"].keys() and \
       this.scans[scan_id]["options"]["fast_scan"]):
        for down_ip in down_ips:
            target = {
                "addr": [down_ip],
                "addr_type": "tcp",
            }
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                                           "Host '{}' is down".format(down_ip),
                                           "The scan detected that the host {} was down".format(down_ip),
                                           type="host_availability",
                                           severity="low")))

    return res, raw_hosts


def _get_cpe_link(cpe):
    return "https://nvd.nist.gov/vuln/search/results?adv_search=true&cpe={}".format(cpe)


# custom functions for Vulners issues
def _get_vulners_findings(findings):
    max_cvss = 0.0
    cve_list = []
    cve_links = []
    cpe_info = ""
    for line in findings.splitlines():
        cols = line.split('\t\t', 2)
        vulners_cve = cols[0].strip()
        if vulners_cve.startswith('cpe'):
            cpe_info = line.strip()
        if vulners_cve.startswith('CVE-'):
            vulners_cvss = float(cols[1])
            if vulners_cvss > max_cvss:
                max_cvss = vulners_cvss
            cve_list.append(vulners_cve)
            cve_links.append(cols[2].strip())
    return float(max_cvss), sorted(cve_list), sorted(cve_links), cpe_info


@app.route('/engines/nmap/getfindings/<scan_id>')
def getfindings(scan_id):
    """Get findings from engine."""
    res = {"page": "getfindings", "scan_id": scan_id}
    if not scan_id.isdecimal():
        res.update({"status": "error", "reason": "scan_id must be numeric digits only"})
        return jsonify(res)
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    # check if the scan is finished
    status()
    if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        res.update({"status": "error", "reason": "Scan in progress"})
        return jsonify(res)

    # check if the report is available (exists && scan finished)
    report_filename = BASE_DIR + "/results/nmap_{}.xml".format(scan_id)
    if not os.path.exists(report_filename):
        res.update({"status": "error", "reason": "Report file not available"})
        return jsonify(res)

    if "issues" not in this.scans[scan_id].keys():
        res.update({"status": "error", "reason": "Issues not available yet"})
        return jsonify(res)

    issues = this.scans[scan_id]["issues"]
    scan = {
        "scan_id": scan_id
    }
    summary = {
        "nb_issues": len(issues),
        "nb_info": len(issues),
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "engine_name": "nmap",
        "engine_version": this.scanner['version']
    }

    # Store the findings in a file
    with open(f"{BASE_DIR}/results/nmap_{scan_id}.json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # Delete the tmp hosts file (used with -iL argument upon launching nmap)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nmap_hosts_{scan_id}.tmp"
    if os.path.exists(hosts_filename):
        os.remove(hosts_filename)

    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"
    })
    return jsonify(res)


@app.route('/engines/nmap/getreport/<scan_id>')
def getreport(scan_id):
    if scan_id not in this.scans.keys():
        return jsonify({"status": "ERROR", "reason": f"scan_id '{scan_id}' not found"})

    # remove the scan from the active scan list
    clean_scan(scan_id)

    filepath = f"{BASE_DIR}/results/nmap_{scan_id}.json"
    if not os.path.exists(filepath):
        return jsonify({"status": "ERROR", "reason": f"report file for scan_id '{scan_id}' not found"})

    return send_from_directory(
        f"{BASE_DIR}/results",
        f"nmap_{scan_id}.json",
        mimetype='application/json',
        attachment_filename=f"nmap_{scan_id}.json",
        as_attachment=True
    )


@app.route('/engines/nmap/test')
def test():
    res = "<h2>Test Page (DEBUG):</h2>"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urllib.request.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if os.getuid() != 0:
        app.logger.error("Start the NMAP engine using root privileges !")
#        sys.exit(-1)
    if not os.path.exists(f"{BASE_DIR}/results"):
        os.makedirs(f"{BASE_DIR}/results")
    if not os.path.exists(f"{BASE_DIR}/tmp"):
        os.makedirs(f"{BASE_DIR}/tmp")
    loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
