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
from shlex import quote
import json

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5021
APP_MAXSCANS = 20
APP_ENGINE_NAME = "patrowl-droopescan"

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.proc = None  # to delete
this.scanner = {}
this.scan_id = 1
this.scans = {}


engine = PatrowlEngine(
    app=app,
    base_dir=BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

#request.packages.urllib3.disable_warnings()



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
    res = {"page": "clean_scan"}
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)



@app.route('/engines/droopescan/status')
def status():
    res = {"page": "status"}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
    else:
        this.scanner['status'] = "READY"

    if not os.path.exists(BASE_DIR+'/droopescan.json'):
        this.scanner['status'] = "ERROR"
#    if not os.path.isfile(this.scanner['path']):
#        this.scanner['status'] = "ERROR"

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

    filepath = BASE_DIR+"/results/droopescan-"+scan_id+".json"
    if not os.path.exists(filepath):
        return jsonify({"status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_file(
        filepath,
        mimetype='application/json',
        attachment_filename='droopescan-'+str(scan_id)+".json",
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
#    if not os.path.isfile(this.scanner['path']):
#        this.scanner['status'] = "ERROR"
#        # print ("Error: path to Droopescan '{}' not found".format(this.scanner['path']))
#        return {"status": "ERROR", "reason": "path to Droopescan binary not found."}


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
    res = {"page": "scan_status", "status": "UNKNOWN"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    if this.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    if not hasattr(proc, "pid"):
        res.update({"status": "ERROR", "reason": "No PID found"})
        return jsonify(res)

    if not psutil.pid_exists(proc.pid):
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"

    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        res.update({
            "status": "SCANNING",
            "info": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"]}
        })

    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() == "zombie":
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"
        psutil.Process(proc.pid).terminate()

    # return the scan parameters and the status
    #res.update({
    #    "scan": this.scans[scan_id],
    #    #"status": this.scans[scan_id]["status"]
    #})

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
                hosts.append("{uri.netloc}".format(uri=urlparse(quote(asset["value"]))).strip())
                app.logger.debug('Adding URL {} to hosts'.format(asset["value"]))
            else:
                hosts.append(quote(asset["value"]).strip())
                app.logger.debug('Adding asset {} to hosts'.format(asset["value"]))

    app.logger.debug('Hosts set : %s', hosts)
    # ensure no duplicates
    hosts = list(set(hosts))

    # write hosts in a file (cleaner and doesn't break with shell arguments limit (for thousands of hosts)
    hosts_filename = BASE_DIR+"/tmp/engine_droopescan_hosts_file_scan_id_{}.tmp".format(scan_id)
    with open(hosts_filename, 'w') as hosts_file:
        for item in hosts:
            hosts_file.write("{}\n".format(quote(item)))

    # Sanitize args :
    options = this.scans[scan_id]['options']
    app.logger.debug('options: %s', options)

    log_path = BASE_DIR+"/results/droopescan-" + scan_id + ".json"

    error_log_path = BASE_DIR+"/logs/droopescan-error-" + scan_id + ".log"

    cmd = "droopescan "
    
    # Check options
    for opt_key in options.keys():  
        if opt_key in this.scanner['options'] and options.get(opt_key):
            # FIXME Security : Is it secure to let any options in ? No escaping ?
            cmd += " {}".format(this.scanner['options'][opt_key]['value'])
        if opt_key ==  "host_file_path":
            if os.path.isfile(options.get(opt_key)):
                with open(options.get(opt_key), 'r') as fh:
                    with open(hosts_filename, 'a') as hosts_file:
                        for line in fh:
                            hosts_file.write(quote(line))

    cmd += " -U " + hosts_filename
    cmd += " --output json "
    app.logger.debug('cmd: %s', cmd)

    this.scans[scan_id]["proc_cmd"] = "not set!!"
    with open(error_log_path, "w") as stderr:
        this.scans[scan_id]["proc"] = subprocess.Popen([cmd], shell=True, stdout=open(log_path, "w"), stderr=stderr)
    this.scans[scan_id]["proc_cmd"] = cmd

    return True


###########################

#Parse Droopescan report
###########################
def _parse_report(filename, scan_id):
    """Parse the Droopescan report."""
    res = []
    target = {}
    app.logger.debug('Opening results file for scan %s', str(scan_id) + " : " + str(filename))
    if os.path.isfile(filename):
        # TODO Catch Exception for open() function
        with open(filename, 'r') as fp:
            app.logger.debug('Opened file named {} in mode {}'.format(fp.name, fp.mode))
            try:
                json_data = json.load(fp)
            except ValueError:
                app.logger.debug('Error happened - DecodeJSONError : {}'.format(sys.exc_info()[0]))
                return {"status" : "error", "reason": "Decoding JSON failed"}
            except NameError:
                app.logger.debug('Error happened - NameError while loading JSON : {}'.format(sys.exc_info()[0]))
                return {"status" : "error", "reason": "NameError"}
            except Exception:
                app.logger.debug('Error happened - {}'.format(sys.exc_info()[0]))
                return {"status" : "error", "reason": "An error occurred"}

            ts = 0 # FIXME tree.find("taskbegin").get("time")
            url_asset = this.scans[scan_id]["assets"]

            addr_list = []
            addr_list.append(str(json_data["host"]))
            addr_type = "url"
            #addr_list.append("https://"+str(json_data["host"]))

                
            target = {
                "addr": addr_list,
                "addr_type" : "url",
            }
    
            has_plugins = False
            if json_data["plugins"]["is_empty"] is False: 
                has_plugins = True
                for fd in json_data["plugins"]["finds"]:
                    plg_name=fd["name"]
                    app.logger.debug('Plugin {} is installed'.format(plg_name))
                    if hasattr(fd,'imu'):
                        desc='The scan detected that the plugin {} is installed on this CMS ({}).'.format(plg_name,fd["imu"]["description"]),
                    else:
                        desc='The scan detected that the plugin {} is installed on this CMS.'.format(plg_name),
                    # Add plugin found to findings
                    res.append(deepcopy(_add_issue(scan_id, target, ts, 
                        'Plugin {} is installed'.format(plg_name), 
                        desc, type='intalled_plugin')))  

            has_themes = False
            if json_data["themes"]["is_empty"] is False:
                has_themes = True
                for fd in json_data["themes"]["finds"]:
                    thm_name=fd["name"]
                    thm_url=fd["url"]
                    app.logger.debug('Theme {} is installed'.format(thm_name))
                    # Add theme found to findings
                    res.append(deepcopy(_add_issue(scan_id, target, ts, 
                        'Theme {} is installed'.format(thm_name), 
                        'The scan detected that the theme {} is installed on {}.'.format(thm_name, thm_url), 
                        type='intalled_theme')))

            # TODO Check host availability
            #if False:
            #   res.append(deepcopy(_add_issue(scan_id, target, ts, 
            #        "Host is up", 
            #        "The scan detected that the host was up", 
            #        type="host_availability"))) 

            has_version = False
            if json_data["version"]["is_empty"] is False:
                has_version = True
                version_list = json_data["version"]["finds"]
                for ver in version_list:
                    app.logger.debug('Version {} is possibly installed'.format(ver))
                    # Add version found to findings
                    res.append(deepcopy(_add_issue(scan_id, target, ts, 
                        'Version {} is possibly installed'.format(ver), 
                        'The scan detected that the version {} is possibly installed.'.format(ver), 
                        type='intalled_version', confidence='low')))

        return res
    else:
        return {"status" : "error", "reason": "An error happened while handling file"}

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
        res.update({"status": "error", "reason": "Scan in progress"})
        return jsonify(res)

    # check if the report is available (exists && scan finished)
    report_filename = BASE_DIR + "/results/droopescan-{}.json".format(scan_id)
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

