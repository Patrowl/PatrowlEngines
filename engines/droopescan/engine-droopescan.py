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
import hashlib
import datetime
from urllib.parse import urlparse
from copy import deepcopy
from flask import Flask, request, jsonify, redirect, url_for, send_file
import xml.etree.ElementTree as ET

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5021
APP_MAXSCANS = 20

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.proc = None  # to delete
this.scanner = {}
this.scan_id = 1
this.scans = {}


engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

requests.packages.urllib3.disable_warnings()



@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    return engine.page_not_found()


@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    """Invalid request usage."""
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response


@app.route('/')
def default():
    """Route by default."""
    return engine.default()


@app.route('/engines/droopescan/')
def index():
    """Return index page."""
    return engine.index()

@app.route('/engines/droopescan/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/droopescan/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/droopescan/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/droopescan/info')
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


@app.route('/engines/droopescan/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/droopescan/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)



@app.route('/engines/droopescan/status')
def status():
    res = {"page": "status"}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
    else:
        this.scanner['status'] = "READY"

    if not os.path.exists(BASE_DIR+'/droopescan.json'):
        this.scanner['status'] = "ERROR"
    if not os.path.isfile(this.scanner['path']):
        this.scanner['status'] = "ERROR"

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



@app.route('/engines/droopescan/getreport/<scan_id>')
def getreport(scan_id):
    if scan_id not in this.scans.keys():
        return jsonify({"status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})

    # remove the scan from the active scan list
    clean_scan(scan_id)

    filepath = BASE_DIR+"/results/droopescan_"+scan_id+".json"
    if not os.path.exists(filepath):
        return jsonify({"status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_file(
        filepath,
        mimetype='application/json',
        attachment_filename='droopescan_'+str(scan_id)+".json",
        as_attachment=True
    )

def loadconfig():
    conf_file = BASE_DIR+'/droopescan.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
    else:
        this.scanner['status'] = "ERROR"
        # print ("Error: config file '{}' not found".format(conf_file))
        return {"status": "ERROR", "reason": "config file not found."}
    if not os.path.isfile(this.scanner['path']):
        this.scanner['status'] = "ERROR"
        # print ("Error: path to Droopescan '{}' not found".format(this.scanner['path']))
        return {"status": "ERROR", "reason": "path to droopescan binary not found."}

def loadconfig():
    conf_file = BASE_DIR+'/droopescan.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
    else:
        this.scanner['status'] = "ERROR"
        # print ("Error: config file '{}' not found".format(conf_file))
        return {"status": "ERROR", "reason": "config file not found."}
    if not os.path.isfile(this.scanner['path']):
        this.scanner['status'] = "ERROR"
        # print ("Error: path to Droopescan '{}' not found".format(this.scanner['path']))
        return {"status": "ERROR", "reason": "path to Droopescan binary not found."}


@app.route('/engines/droopescan/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}
    loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.route('/engines/droopescan/test')
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



@app.route('/engines/droopescan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    res = {"page": "scan_status"}

    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check id the scan is finished or not
    _is_scan_finished(scan_id)

    # return the scan parameters and the status
    res.update({
        # "scan": engine.scans[scan_id],
        "status": engine.scans[scan_id]["status"]
    })

    return jsonify(res)


def _add_issue(scan_id, target, ts, title, desc, type, severity="info", confidence="certain", vuln_refs={}, links=[], tags=[], risk={}):
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

# Stop all scans
@app.route('/engines/droopescan/stopscans')
def stop():
    res = {"page": "stopscans"}

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})

    return jsonify(res)


@app.route('/engines/droopescan/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "stopscan"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]
    if hasattr(proc, 'pid'):
        # his.proc.terminate()
        # proc.kill()
        # os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        if psutil.pid_exists(proc.pid):
            psutil.Process(proc.pid).terminate()
        res.update({"status": "TERMINATED",
            "details": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"],
                "scan_id": scan_id}
        })
    return jsonify(res)




##########################
@app.route('/engines/droopescan/startscan', methods=['POST'])
def start():
    res = {"page": "startscan"}

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
            "details": {
                "reason": "scanner not ready",
                "status": this.scanner['status']
        }})
        return jsonify(res)

    # Load scan parameters
    data = json.loads(request.data.decode("UTF-8"))
    if 'assets' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
        }})
        return jsonify(res)

    scan_id = str(data['scan_id'])
    if data['scan_id'] in this.scans.keys():
        res.update({
            "status": "refused",
            "details": {
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
                    "reason": "datatype '{}' not supported for the asset {}.".format(asset["datatype"], asset["value"])
            }})
	#commentaire = ''' To delete, somtimes we scan app like https://example.com/app1name/ only and nor https://example.com'''
        else:
            # extract the net location from urls if needed
            if asset["datatype"] == 'url':
                hosts.append("{uri.netloc}".format(uri=urlparse(asset["value"])).strip())
            else:
                hosts.append(asset["value"].strip())

    # ensure no duplicates
    hosts = list(set(hosts))

    # write hosts in a file (cleaner and doesn't break with shell arguments limit (for thousands of hosts)
    hosts_filename = BASE_DIR+"/tmp/engine_droopescan_hosts_file_scan_id_{}.tmp".format(scan_id)
    with open(hosts_filename, 'w') as hosts_file:
        for item in hosts:
            hosts_file.write("%s\n" % item)
            app.logger.debug('asset: %s', item)

    # Sanitize args :
    # del this.scans[scan_id]['options']['ports']
    options = this.scans[scan_id]['options']
    app.logger.debug('options: %s', options)

    log_path = BASE_DIR+"/logs/" + scan_id + ".error"

    cmd = this.scanner['path'] + " scan "

''' NO OPTIONS FOR THIS SCAN
    # Check options
    for opt_key in options.keys():
        if opt_key in this.scanner['options'] and options.get(opt_key) and opt_key not in ["ports", "script", "top_ports", "script_args", "script_output_fields", "host_file_path"]:
            cmd += " {}".format(this.scanner['options'][opt_key]['value'])
        if opt_key == "ports" and ports is not None:  # /!\ @todo / Security issue: Sanitize parameters here
            cmd += " -p{}".format(ports)
        if opt_key == "top_ports": # /!\ @todo / Security issue: Sanitize parameters here
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
'''

    cmd += " -U " + hosts_filename
    cmd += " > " +BASE_DIR+"/results/droopescanOut_" + scan_id + ".json"
    app.logger.debug('cmd: %s', cmd)

    this.scans[scan_id]["proc_cmd"] = "not set!!"
    with open(log_path, "w") as stderr:
        this.scans[scan_id]["proc"] = subprocess.Popen(cmd, shell=True, stdout=open("/dev/null", "w"), stderr=stderr)
    this.scans[scan_id]["proc_cmd"] = cmd

    return True


###########################

#Parse Droopescan report
###########################
def _parse_report(filename, scan_id):
    """Parse the Droopescan report."""
    res = []
    target = {'https://testsite.com'}
    ts = tree.find("taskbegin").get("time")



    if True:
    	res.append(deepcopy(_add_issue(scan_id, target, ts,
    	"Host is up",
    	"The scan detected that the host was up",
    	type="host_availability")))

    return res


###########################

@app.route('/engines/droopescan/getfindings/<scan_id>')
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    # check if the scan is finished
    status()
    if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        # print "scan not finished"
        res.update({"status": "error", "reason": "Scan in progress"})
        return jsonify(res)

    # check if the report is available (exists && scan finished)
    report_filename = BASE_DIR + "/results/droopescanOut_{}.json".format(scan_id)
    if not os.path.exists(report_filename):
        res.update({"status": "error", "reason": "Report file not available"})
        return jsonify(res)

    issues = _parse_report(report_filename, scan_id)
    scan = {
        "scan_id": scan_id
    }
    summary = {
        "nb_issues": len(issues),
        "nb_info": len(issues),
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "engine_name": "droopescan",
        "engine_version": this.scanner['version']
    }

    # Store the findings in a file
    with open(BASE_DIR+"/results/droopescan_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)


    # Delete the tmp hosts file (used with -iL argument upon launching Droopescan)
    hosts_filename = BASE_DIR+"/tmp/engine_droopescan_hosts_file_scan_id_{}.tmp".format(scan_id)
    if os.path.exists(hosts_filename):
        os.remove(hosts_filename)


    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"
        })
    return jsonify(res)


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    if not os.path.exists(BASE_DIR+"/tmp"):
        os.makedirs(BASE_DIR+"/tmp")
    loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))

