#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, json, time, datetime, threading, random, requests, urllib, urlparse, optparse
import xml.etree.ElementTree as ElementTree
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5008
APP_MAXSCANS = 5

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scans = {}
this.keys = []

@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/urlvoid/', methods=['GET'])
def index():
    return jsonify({ "page": "index" })


def _loadconfig():
    conf_file = BASE_DIR+'/urlvoid.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)

        for apikey in this.scanner["apikeys"]:
            this.keys.append(apikey)
        del this.scanner["apikeys"]
        this.scanner['status'] = "READY"
        print(this.scanner)

    else:
        print ()"Error: config file '{}' not found".format(conf_file))
        return { "status": "error", "reason": "config file not found" }


@app.route('/engines/urlvoid/reloadconfig', methods=['GET'])
def reloadconfig():
    res = { "page": "reloadconfig" }
    _loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/urlvoid/startscan', methods=['POST'])
def start_scan():
    #@todo: validate parameters and options format
    res = { "page": "startscan" }

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)

    status()
    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details" : {
                "reason": "scanner not ready",
                "status": this.scanner['status']
        }})
        return jsonify(res)

    data = json.loads(request.data)
    if not 'assets' in data.keys():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "arg error, something is missing ('assets' ?)"
        }})
        return jsonify(res)

    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
			res.update({
    			"status": "error",
    			"reason": "arg error, something is missing ('asset.value')"
    		})
			return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in this.scanner["allowed_asset_types"]:
            res.update({
    			"status": "error",
    			"reason": "arg error, bad value for '{}' datatype (not supported)".format(asset["value"])
    		})
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
        # 'assets':       data['assets'],
        'assets':       [a['value'] for a in data['assets']],
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'findings':     {}
    }

    this.scans.update({scan_id: scan})
    th = threading.Thread(target=_scan_urls, args=(scan_id,))
    th.start()
    this.scans[scan_id]['threads'].append(th)

    res.update({
        "status": "accepted",
        "details" : {
            "scan_id": scan['scan_id']
    }})

    return jsonify(res)

def _scan_urls(scan_id):
    assets = []
    for asset in this.scans[scan_id]['assets']:
        assets.append(asset)

    for asset in assets:
        if not asset in this.scans[scan_id]["findings"]: this.scans[scan_id]["findings"][asset] = {}
        try:
            this.scans[scan_id]["findings"][asset]['issues'] = get_report(asset,this.keys[random.randint(0,len(this.keys)-1)])
        except:
            print "API Connexion error (quota?)"; return False

    return True

def get_report(asset,apikey):
    xml = requests.get("http://api.urlvoid.com/api1000/"+apikey+"/host/"+asset+"/")
    issues = []
    tree = ElementTree.fromstring(xml.text)
    if tree.find("detections/engines") is not None:
        for child in tree.find("detections/engines"):
            issues.append(child.text)

    return issues


# Stop all scans
@app.route('/engines/urlvoid/stopscans', methods=['GET'])
def stop():
    res = { "page": "stopscans" }

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})

    return jsonify(res)


@app.route('/engines/urlvoid/stop/<scan_id>', methods=['GET'])
def stop_scan(scan_id):
    res = { "page": "stop" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    scan_status(scan_id)
    if this.scans[scan_id]['status'] != "SCANNING":
        res.update({ "status": "error", "reason": "scan '{}' is not running (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    for t in this.scans[scan_id]['threads']:
        t._Thread__stop()
    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    res.update({"status": "success"})
    return jsonify(res)


@app.route('/engines/urlvoid/clean', methods=['GET'])
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/urlvoid/clean/<scan_id>', methods=['GET'])
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/urlvoid/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)})

    all_threads_finished = False
    for t in this.scans[scan_id]['threads']:
        if t.isAlive():
            this.scans[scan_id]['status'] = "SCANNING"
            all_threads_finished = False
            break
        else:
            all_threads_finished = True

    if all_threads_finished and len(this.scans[scan_id]['threads']) >=1 and this.scans[scan_id]['status'] != "STOPPED":
        this.scans[scan_id]['status'] = "FINISHED"
        this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    return jsonify({"status": this.scans[scan_id]['status']})


@app.route('/engines/urlvoid/status', methods=['GET'])
def status():
    res = {    "page": "status"}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
    else:
        this.scanner['status'] = "READY"

    scans = []
    for scan_id in this.scans.keys():
        scan_status(scan_id)
        scans.append({scan_id: {
            "status": this.scans[scan_id]['status'],
            "started_at": this.scans[scan_id]['started_at'],
            "assets": this.scans[scan_id]['assets']
        }})

    res.update({
        "nb_scans": len(this.scans),
        "status": this.scanner['status'],
        "scanner": this.scanner,
        "scans": scans})

    return jsonify(res)


@app.route('/engines/urlvoid/info', methods=['GET'])
def info():
    status()
    return jsonify({"page": "info", "engine_config": this.scanner})


def _parse_results(scan_id):
    issues = []
    summary = {}

    scan = this.scans[scan_id]
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    ts = int(time.time() * 1000)

    for asset in this.scans[scan_id]["findings"]:
        if len(this.scans[scan_id]["findings"][asset]["issues"]) != 0:
            description = "On the host {} appear in {} identified in blacklist engines or online reputation tools :\n".format(asset, len(this.scans[scan_id]["findings"][asset]["issues"]))
            for engine in this.scans[scan_id]["findings"][asset]["issues"]:
                description = description + engine + "\n"
            description = description + "For more detail go 'http://www.urlvoid.com/scan/"+ asset + "/'"
            nb_vulns["high"] += 1
            issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "high", "confidence": "certain",
                    "target": { "addr": [asset], "protocol": "http" },
                    "title": "'{}' identified in urlvoid".format(asset),
                    "solution": "n/a",
                    "metadata": { "tags": ["http"] },
                    "type": "urlvoid_report",
                    "timestamp": ts,
                    "description": description
                }
            )
        else:
            nb_vulns["info"] += 1
            issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "info", "confidence": "certain",
                    "target": { "addr": [asset], "protocol": "http" },
                    "title": "'{}' have not been identified in urlvoid".format(asset),
                    "solution": "n/a",
                    "metadata": { "tags": ["http"] },
                    "type": "urlvoid_report",
                    "timestamp": ts,
                    "description": "{} have not identified in blacklist engines or online reputation tools".format(asset)
                }
            )

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "urlvoid",
        "engine_version": this.scanner["version"]
    }

    return issues, summary


@app.route('/engines/urlvoid/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = { "page": "getfindings", "scan_id": scan_id }

    # check if the scan_id exists
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    status()
    if this.scans[scan_id]['status'] != "FINISHED":
        res.update({ "status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    issues, summary =  _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": this.scans[scan_id]['assets'],
        "options": this.scans[scan_id]['options'],
        "status": this.scans[scan_id]['status'],
        "started_at": this.scans[scan_id]['started_at'],
        "finished_at": this.scans[scan_id]['finished_at']
    }

    #Store the findings in a file
    with open(BASE_DIR+"/results/urlvoid_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({ "scan": scan, "summary": summary, "issues": issues, "status": "success"})
    return jsonify(res)


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable ({})".format(obj))


@app.route('/engines/urlvoid/getreport/<scan_id>', methods=['GET'])
def getreport(scan_id):
    filepath = BASE_DIR+"/results/urlvoid_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_from_directory(BASE_DIR+"/results/", "urlvoid_"+scan_id+".json")


@app.route('/engines/urlvoid/test', methods=['GET'])
def test():
    if not APP_DEBUG:
        return jsonify({"page": "test"})

    res = "<h2>Test Page (DEBUG):</h2>"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urlparse.unquote("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
