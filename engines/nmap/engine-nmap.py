#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, subprocess, signal, sys, psutil, json, uuid, optparse, threading, urllib, time, hashlib
from urlparse import urlparse
from copy import deepcopy
from flask import Flask, request, jsonify, redirect, url_for, send_file
import xml.etree.ElementTree as ET

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5001
APP_MAXSCANS = 20

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.proc = None # to delete
this.scanner = {}
this.scan_id = 1
this.scans = {}

'''
# inputs:
{"assets": [{
    "id" :'3',
    "value" :'8.8.8.8',
    "criticity": 'low',
    "datatype": 'ip'
    }, {...}],
 "options": {
    "ports": ['53', '56', '80', '443', '8080'],
    "no_ping": True,
    "no_dns": True,
    "scan_udp": True,
    "detect_service_version": True,
    "detect_os": True,
    "script_scan": True }
 }

# outputs:
{"page": "report",
"scan_id": 1212,
"status": "success",
"issues": [{
    "issue_id": 1,
    "severity": 'high',
    "confidence": 'certain',
    "target": {
        "addr": 8.8.8.8,
        "addr_type": 'ipv4',
        "hostnames": [ 'google-dns-a.google.com']
    },
    "title": 'host is up',
    "description": 'The host 8.8.8.8 has been found alive',
    "type": 'host_availability',
    "timestamp": 143545645775
}]}

'''

# Generic functions
def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


# Route actions
@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/nmap/')
def index():
    return jsonify({ "page": "index" })


def loadconfig():
    conf_file = BASE_DIR+'/nmap.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
    else:
        print "Error: config file '{}' not found".format(conf_file)
        return { "status": "ERROR", "reason": "config file not found" }


@app.route('/engines/nmap/reloadconfig')
def reloadconfig():
    res = { "page": "reloadconfig" }
    loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/nmap/startscan', methods=['POST'])
def start():
    #@todo: validate parameters and options format
    res = { "page": "startscan" }


    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)

    # update scanner status
    status()

    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details" : {
                "reason": "scanner not ready",
                "status": this.scanner['status']
        }})
        return jsonify(res)

    # Load scan parameters
    data = json.loads(request.data)
    if not 'assets' in data.keys():# or not data['options']['ports']:
        res.update({
            "status": "refused",
            "details" : {
                "reason": "arg error, something is missing ('assets' ?)"
        }})
        return jsonify(res)

    scan_id = str(data['scan_id'])
    if data['scan_id'] in this.scans.keys():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "scan '{}' already launched".format(data['scan_id']),
        }})
        return jsonify(res)

    scan = {
        'assets':       data['assets'],
        'threads':      [],
        'proc':         None,
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'nb_findings':  0
    }

    this.scans.update({scan_id: scan})
    th = threading.Thread(target=_scan_thread, args=(scan_id,))
    th.start()
    this.scans[scan_id]['threads'].append(th)

    res.update({
        "status": "accepted",
        "details" : {
            "scan_id": scan['scan_id']
    }})

    return jsonify(res)


def _scan_thread(scan_id):
    hosts = []

    for asset in this.scans[scan_id]['assets']:
        if asset["datatype"] not in this.scanner["allowed_asset_types"]:
            return jsonify({
                    "status": "refused",
                    "details" : {
                        "reason": "datatype '{}' not supported for the asset {}.".format(asset["datatype"], asset["value"])
                }})
        else:
            # extract the net location from urls if needed
            if asset["datatype"] == 'url':
                hosts.append("{uri.netloc}".format(uri=urlparse(asset["value"])).strip())
            else:
                hosts.append(asset["value"].strip())

    # ensure no duplicates
    hosts = list(set(hosts))

    # Sanitize args :
    ports = None
    if "ports" in this.scans[scan_id]['options'].keys():
        ports = ",".join(this.scans[scan_id]['options']['ports'])
    #del this.scans[scan_id]['options']['ports']
    options = this.scans[scan_id]['options']
    log_path = BASE_DIR+"/logs/" + scan_id +".error"

    cmd = this.scanner['path'] + " -vvv " + " ".join(hosts) + \
        " -oX "+BASE_DIR+"/results/nmap_" + scan_id + ".xml"

    # Check options
    for opt_key in options.keys():
        if opt_key in this.scanner['options'] and options.get(opt_key) and opt_key not in ["ports", "script", "script_args", "script_output_fields"]:
            cmd += " {}".format(this.scanner['options'][opt_key]['value'])
        if opt_key == "ports" and ports is not None: # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " -p{}".format(ports)
        if opt_key == "script" and options.get(opt_key).endswith('.nse'): # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script {}".format(options.get(opt_key))
        if opt_key == "script_args": # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " --script-args {}".format(options.get(opt_key))



    with open(log_path, "w") as stderr:
        this.scans[scan_id]["proc"] = subprocess.Popen(cmd, shell=True, stdout=open("/dev/null", "w"), stderr=None)
    this.scans[scan_id]["proc_cmd"] = cmd

    return True


@app.route('/engines/nmap/clean')
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    return jsonify(res)


@app.route('/engines/nmap/clean/<scan_id>')
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/nmap/stopscans')
def stop():
    res = { "page": "stopscans" }

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({ "status": "SUCCESS" })

    return jsonify(res)


@app.route('/engines/nmap/stop/<scan_id>')
def stop_scan(scan_id):
    res = { "page": "stopscan" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]
    if hasattr(proc, 'pid'):
        #his.proc.terminate()
        #proc.kill()
        #os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        if psutil.pid_exists(proc.pid):
            psutil.Process(proc.pid).terminate()
        res.update({"status" : "TERMINATED",
            "details": {
                "pid" : proc.pid,
                "cmd" : this.scans[scan_id]["proc_cmd"],
                "scan_id": scan_id}
        })
    return jsonify(res)


@app.route('/engines/nmap/status/<scan_id>')
def scan_status(scan_id):
    res = {"page": "status", "status": "UNKNOWN"}
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    if this.scans[scan_id]["status"] == "ERROR":
        res.update({ "status": "error", "reason": "todo"})
        return jsonify(res)

    if hasattr(proc, 'pid'):
        #print(psutil.Process(proc.pid).status())
        if not psutil.pid_exists(proc.pid):
            res.update({"status" : "FINISHED" })
            this.scans[scan_id]["status"] = "FINISHED"

        elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
            res.update({
                "status" : "SCANNING",
                "info": {
                    "pid" : proc.pid,
                    "cmd": this.scans[scan_id]["proc_cmd"] }
            })
        elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() == "zombie":
            res.update({"status" : "FINISHED" })
            this.scans[scan_id]["status"] = "FINISHED"
            psutil.Process(proc.pid).terminate()
            #Check for errors
            # log_path = BASE_DIR+"/logs/" + scan_id +".error"
            #
            # if os.path.isfile(log_path) and os.stat(log_path).st_size != 0:
            #     error = open(log_path, 'r')
            #     res.update({
            #         "status" : "error",
            #         "details": {
            #             "error_output" : error.read(),
            #             "scan_id": scan_id,
            #             "cmd": this.scans[scan_id]["proc_cmd"] }
            #     })
            #     stop()
            #     os.remove(log_path)
            #     res.update({ "status": "READY" })
    else:
        res.update({ "status": "UNKNOWN" })
    return jsonify(res)


@app.route('/engines/nmap/status')
def status():
    res = {"page": "status"}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
    else:
        this.scanner['status'] = "READY"

    res.update({"status": this.scanner['status']})

    # display info on the scanner
    res.update({"scanner": this.scanner})

    # display the status of scans performed
    scans = {}
    for scan in this.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": this.scans[scan]["status"],
            "proc_cmd": this.scans[scan]["proc_cmd"],
            "assets": this.scans[scan]["assets"],
            "options": this.scans[scan]["options"],
            "nb_findings": this.scans[scan]["nb_findings"],
        }})
    res.update({"scans": scans})
    return jsonify(res)


@app.route('/engines/nmap/info')
def info():
    res = { "page": "info",
           "engine_config": this.scanner,
           "scans": this.scans
           }
    # if this.proc and not this.proc.poll():
    #     res.update({ "proc": { "pid" : this.proc.pid }})
    # else:
    #     res.update({ "proc": None })
    return jsonify(res)


def _add_issue(scan_id, target, ts, title, desc, type, severity = "info", confidence = "certain", vuln_refs = {}, links = [], tags = [], risk = {}):
    this.scans[scan_id]["nb_findings"] = this.scans[scan_id]["nb_findings"] + 1
    issue = {
        "issue_id": this.scans[scan_id]["nb_findings"],
        "severity": severity,
        "confidence": confidence,
        "target": target,
        "title": title,
        "description": desc,
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
    res = []
    target = {}
    try:
        tree = ET.parse(filename)
    except:
        # No Element found in XML file
        return { "status": "ERROR", "reason": "no issues found" }

    ts = tree.find("taskbegin").get("time")

    skip_issue = False
    for host in tree.findall('host'):
        skip_issue = False
        # get startdate of the host scan
        #ts = host.get('starttime')

        addr_list = []
        addr_type = host.find('address').get('addrtype')

        has_hostnames = False
        # find hostnames
        for hostnames in host.findall('hostnames'):
            for hostname in hostnames._children:
                if hostname.get("type") == "user":
                    has_hostnames = True
                    addr = hostname.get("name")
                    addr_list.append(hostname.get("name"))

        # get IP address otherwise
        if not has_hostnames:
            addr = host.find('address').get('addr')
            addr_list.append(addr)

        # Check if it was extracted from URLs. If yes: add them
        for a in this.scans[scan_id]["assets"]:
            if a["datatype"] == "url" and urlparse(a["value"]).netloc in addr_list:
                addr_list.append(a["value"])

        target = {
            "addr": addr_list,
            "addr_type": addr_type,
        }

        # get host status
        status = host.find('status').get('state')
        if status and status == "up":
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                "Host '{}' is up".format(addr),
                "The scan detected that the host {} was up".format(addr),
                type="host_availability")))
        else:
            res.append(deepcopy(_add_issue(scan_id, target, ts,
                "Host '{}' is down".format(addr),
                "The scan detected that the host {} was down".format(addr),
                type="host_availability")))

        # get OS information
        if host.find('os') is not None:
            osinfo = host.find('os').find('osmatch')
            if osinfo is not None:
                res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "OS: {}".format(osinfo.get('name')),
                    "The scan detected that the host run in OS '{}' (accuracy={}%)"
                        .format(osinfo.get('name'), osinfo.get('accuracy')),
                    type="host_osinfo",
                    confidence="undefined")))

        # get ports status - generate issues
        if host.find('ports') is not None:
            for port in host.find('ports'):
            # for port in host.find('ports'):
                if port.tag == 'extraports': continue
                proto = port.get('protocol')
                portid = port.get('portid')
                port_state = port.find('state').get('state')

                target.update({
                    "protocol": proto,
                    "port_id": portid,
                    "port_state": port_state })

                res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "Port '{}/{}' is {}".format(proto, portid, port_state),
                    "The scan detected that the port '{}/{}' was {}".format(proto, portid, port_state),
                    type="port_status")))

                # get service information if available
                if port.find('service') is not None and port.find('state').get('state') not in ["filtered", "closed"]:
                    svc_name = port.find('service').get('name')
                    target.update({ "service": svc_name })

                    # Check if a CPE has been identified
                    cpe_info=""
                    cpe_link=None
                    cpe_refs={}
                    if port.find('service').find("cpe") is not None:
                        cpe_vector = port.find('service').find("cpe").text
                        cpe_link = _get_cpe_link(cpe_vector)
                        cpe_info = "\n The following CPE vector has been identified: {}".format(cpe_vector)
                        cpe_refs={"CPE": [cpe_vector]}

                    res.append(deepcopy(_add_issue(scan_id, target, ts,
                        "Service '{}' is running on port '{}/{}'".format(svc_name, proto, portid),
                        "The scan detected that the service '{}' is running on port '{}/{}'. {}"
                            .format(svc_name, proto, portid, cpe_info),
                        type="port_info",
                        links=[cpe_link],
                        vuln_refs=cpe_refs)))

                for port_script in port.findall('script'):
                    script_id = port_script.get('id')
                    script_output = port_script.get('output')
                    script_hash = hashlib.sha1(script_output).hexdigest()[:6]

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
                            "Nmap script '{}' detected findings on port {}/{} (HASH: {})".format(script_id, proto, portid, script_hash),
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
                            "Nmap script '{}' detected findings on port {}/{} (HASH: {})".format(script_id, proto, portid, script_hash),
                            "The script '{}' detected following findings:\n{}"
                                .format(script_id, script_output),
                            type="port_script",
                            tags=[script_id])))


        # get script results - generate issues
        if host.find('hostscript') is not None:
            for script in host.find('hostscript'):
                script_output = script.get('output')
                res.append(deepcopy(_add_issue(scan_id, target, ts,
                    "Script '{}' has given results".format(script.get('id')),
                    "The script '{}' revealed following information: \n{}".format(script.get('id'), script_output),
                    type="host_script")))

                if "script_output_fields" in this.scans[scan_id]["options"].keys():
                    for elem in script.findall("elem"):
                        if elem.get("key") in this.scans[scan_id]["options"]["script_output_fields"]:
                            res.append(deepcopy(_add_issue(scan_id, target, ts,
                                "Script results '{}/{}' set to '{}'".format(script.get('id'), elem.get("key"), elem.text),
                                "The script '{}' revealed following information: \n'{}' was identified to '{}'".format(script.get('id'), elem.get("key"), elem.text),
                                type="host_script_advanced")))

    return res

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
            vulners_cvss = cols[1]
            if vulners_cvss > max_cvss: max_cvss = vulners_cvss
            #print "cve:", vulners_cve, "-> cvss:",vulners_cvss
            cve_list.append(vulners_cve)
            cve_links.append(cols[2].strip())
    #print "max_cvss:", max_cvss
    return float(max_cvss), cve_list, cve_links, cpe_info

@app.route('/engines/nmap/getfindings/<scan_id>')
def getfindings(scan_id):
    res = { "page": "getfindings", "scan_id": scan_id }
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    # check if the scan is finished
    status()
    if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        #print "scan not finished"
        res.update({ "status": "error", "reason": "Scan in progress" })
        return jsonify(res)

    # check if the report is available (exists && scan finished)
    report_filename = BASE_DIR + "/results/nmap_{}.xml".format(scan_id)
    if not os.path.exists(report_filename):
        #print "file not found"
        res.update({ "status": "error", "reason": "Report file not available" })
        return jsonify(res)

    issues =  _parse_report(report_filename, scan_id)
    scan = {
        "scan_id": scan_id
    }
    summary = {
        "nb_issues": len(issues),
        "nb_info": len(issues),
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        #"delta_time": "",
        "engine_name": "nmap",
        "engine_version": this.scanner['version']
    }

    # Store the findings in a file
    with open(BASE_DIR+"/results/nmap_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)


    res.update({ "scan": scan })
    res.update({ "summary": summary })
    res.update({ "issues": issues })
    res.update({ "status": "success"})
    return jsonify(res)


@app.route('/engines/nmap/getreport/<scan_id>')
def getreport(scan_id):
    if not scan_id in this.scans.keys():
        return jsonify({ "status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})

    # remove the scan from the active scan list
    clean_scan(scan_id)

    filepath = BASE_DIR+"/results/nmap_"+scan_id+".json"
    if not os.path.exists(filepath):
        return jsonify({ "status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_file(filepath,
        mimetype='application/json',
        attachment_filename='nmap_'+str(scan_id)+".json",
        as_attachment=True)


@app.route('/engines/nmap/test')
def test():
    res = "<h2>Test Page (DEBUG):</h2>"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urllib.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if os.getuid() != 0:
        print "Error: Start the NMAP engine using root privileges !"
        sys.exit(-1)
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
