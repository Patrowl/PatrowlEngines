#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, json, time, datetime, threading, random, requests, urlparse, hashlib, optparse
import xml.etree.ElementTree as ElementTree
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
from cortexapi import CortexApi, CortexException

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5009
APP_MAXSCANS = 100

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}   # Scanner config
this.scans = {}     # Scans list
this.api = None     # Cortex API instance

@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/cortex/')
def index():
    return jsonify({ "page": "index" })


def _loadconfig():
    conf_file = BASE_DIR+'/cortex.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)

        this.api = CortexApi(
            this.scanner["api_url"],
            this.scanner["api_key"],
            proxies=this.scanner["proxies"],
            cert=False)

        this.scanner["status"] = "READY"
        _refresh_analyzers()
    else:
        this.scanner["status"] = "ERROR"
        print ("Error: config file '{}' not found".format(conf_file))
        return { "status": "error", "reason": "config file not found" }


def _refresh_analyzers():
    try:
        analyzers = this.api.get_analyzers()
        this.scanner["analyzers"] = analyzers
    except CortexException as ex:
        this.scanner["status"] = "ERROR"
        print('[ERROR]: Failed to list analyzers ({})'.format(ex.message))
        return False
    return True

@app.route('/engines/cortex/reloadconfig')
def reloadconfig():
    res = { "page": "reloadconfig" }
    _loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/cortex/startscan', methods=['POST'])
def start_scan():
    '''
    List available Cortex Analyzers (refresh)
    Ensure each scans comply with the analyzer (ready, datatype, ...)
    '''
    #@todo: validate parameters and options format
    res = {"page": "startscan"}

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

    # Assets
    if not 'assets' in data.keys():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "arg error, something is missing ('assets' ?)"
        }})
        return jsonify(res)

    # Scan ID
    scan_id = str(data['scan_id'])
    if data['scan_id'] in this.scans.keys():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "scan '{}' already launched".format(data['scan_id']),
        }})
        return jsonify(res)

    # Analyzers availability
    _refresh_analyzers()
    if not _refresh_analyzers():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "Scan refused: having troubles with the Cortex analyzers"
        }})
        return jsonify(res)

    scan = {
        'assets':       data['assets'],
        'threads':      [],
        'jobs':         [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'findings':     []
    }

    this.scans.update({scan_id: scan})
    for asset in data['assets']:
        th = threading.Thread(target=_start_analyzes, args=(scan_id, asset["value"], asset["datatype"]))
        th.start()
        this.scans[scan_id]['threads'].append(th)

    res.update({
        "status": "accepted",
        "details" : {
            "scan_id": scan['scan_id']
    }})

    return jsonify(res)

def _start_analyzes(scan_id, asset, datatype):
    analyzers = []

    # Analyzers selected one by one
    if "use_analyzers" in this.scans[scan_id]["options"] and this.scans[scan_id]["options"]["use_analyzers"]:
        preselected_analyzers = this.scans[scan_id]["options"]["use_analyzers"]

        for analyzer in this.scanner["analyzers"]:
            # Check availability and datatype
            if analyzer["analyzerDefinitionId"] in preselected_analyzers and datatype in analyzer["dataTypeList"]:
                analyzers.append(analyzer["id"])

    if "all_datatype_analyzers" in this.scans[scan_id]["options"] and this.scans[scan_id]["options"]["all_datatype_analyzers"]:
        for analyzer in this.scanner["analyzers"]:
            if datatype in analyzer["dataTypeList"]:
                analyzers.append(analyzer["id"])

    if "meta_analyzers" in this.scans[scan_id]["options"] and this.scans[scan_id]["options"]["meta_analyzers"]:
        for ma in this.scans[scan_id]["options"]["meta_analyzers"]:
            if ma in this.scanner["meta_analyzers"].keys():
                # valid meta-analyzer
                analyzers = analyzers + this.scanner["meta_analyzers"][ma]

    # Run all selected (unique) analyzers
    for analyzer in list(set(analyzers)):
        try:
            resp = this.api.run_analyzer(analyzer, datatype, 1, asset)
            this.scans[scan_id]["jobs"].append(resp["id"])
        except CortexException as ex:
            print('[ERROR]: Failed to run analyzer: {}'.format(ex.message))
            return False

    return True


@app.route('/engines/cortex/stop/<scan_id>')
def stop_scan(scan_id):
    res = { "page": "stop" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    scan_status(scan_id)
    if this.scans[scan_id]['status'] != "SCANNING":
        res.update({ "status": "error", "reason": "scan '{}' is not running (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    for job_id in this.scans[scan_id]['jobs']:
        _clean_job(job_id)

    for t in this.scans[scan_id]['threads']:
        t._Thread__stop()
    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    res.update({"status": "success"})
    return jsonify(res)

# Stop all scans
@app.route('/engines/cortex/stopscans', methods=['GET'])
def stop():
    res = { "page": "stopscans" }

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})

    return jsonify(res)


@app.route('/engines/cortex/clean')
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/cortex/clean/<scan_id>')
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    for job in this.scans[scan_id]["jobs"]:
        _clean_job(job)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


def _clean_job(job_id):
    try:
        r = this.api.delete_job(job_id)
    except CortexException as ex:
        print('[ERROR]: Failed to get job report'.format(ex.message))
    return True


@app.route('/engines/cortex/status/<scan_id>')
def scan_status(scan_id):
    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)})

    for job_id in this.scans[scan_id]['jobs']:
        try:
            r = this.api.get_job_report(job_id)
            if r["status"] in ["Success", "Failure"]:
                this.scans[scan_id]["findings"] = this.scans[scan_id]["findings"] + _parse_results(scan_id, r)
                this.scans[scan_id]["jobs"].remove(job_id)
        except CortexException as ex:
            print('[ERROR]: Failed to get job report'.format(ex.message))

    all_threads_finished = False
    for t in this.scans[scan_id]['threads']:
        if t.isAlive():
            this.scans[scan_id]['status'] = "SCANNING"
            all_threads_finished = False
            break
        else:
            all_threads_finished = True

    if all_threads_finished and len(this.scans[scan_id]['jobs']) == 0 and this.scans[scan_id]['status'] == "SCANNING":
        this.scans[scan_id]['status'] = "FINISHED"
        this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    return jsonify({"status": this.scans[scan_id]['status']})


@app.route('/engines/cortex/status')
def status():
    res = {"page": "status"}

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
        #"scanner": this.scanner,
        "scans": scans})

    return jsonify(res)


@app.route('/engines/cortex/info')
def info():
    status()
    return jsonify({
        "page": "info",
        "engine_config": this.scanner
    })


def _parse_results(scan_id, results):
    issues = []
    scan = this.scans[scan_id]
    ts = int(time.time() * 1000)

    #print ("results: {}".format(results))

    # if failure: return an issue
    if results["status"] == "Failure":
        if "display_failures" in this.scans[scan_id]["options"].keys() and this.scans[scan_id]["options"]["display_failures"] == True:
            issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [results["data"]],
                        "protocol": results["dataType"] },
                    "title": "Failure in '{}' analyze".format(results["analyzerName"]),
                    "solution": "n/a",
                    "metadata": { "tags": [
                        "cortex",
                        results["dataType"],
                        results["analyzerName"]
                        ]
                    },
                    "type": "cortex_report",
                    "timestamp": ts,
                    "description": "Error message: {}".format(results["report"]["full"]["errorMessage"])
                }
            )
        return issues

    # Artifact issue if asked (get_artifacts=True option)
    if "get_artifacts" in this.scans[scan_id]["options"].keys() and this.scans[scan_id]["options"]["get_artifacts"]:
        description = "Following artefacts have been found during the analyze:\n"
        for artefact in results["report"]["artifacts"]:
            description += "\n{} ({})".format(artefact["data"], artefact["dataType"])
        issue_hash = hashlib.sha1(description).hexdigest()[:6]

        issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [results["data"]],
                    "protocol": results["dataType"] },
                "title": "Artefacts from '{}' analyzer (HASH: {})".format(
                    results["analyzerName"],
                    issue_hash
                ),
                "solution": "n/a",
                "metadata": { "tags": [
                    "cortex",
                    results["dataType"],
                    results["analyzerName"]
                    ]
                },
                "type": "cortex_report",
                "timestamp": ts,
                "description": description
            }
        )

    # Taxonomies in summary
    if "taxonomies" in results["report"]["summary"].keys():
        for taxo in results["report"]["summary"]["taxonomies"]:
            severity = "info"
            if taxo["level"] == "info": severity = "info"
            elif taxo["level"] == "safe": severity = "info"
            elif taxo["level"] == "suspicious": severity = "medium"
            elif taxo["level"] == "malicious": severity = "high"

            issues.append({
                    "issue_id": len(issues)+1,
                    "severity": severity, "confidence": "certain",
                    "target": {
                        "addr": [results["data"]],
                        "protocol": results["dataType"] },
                    "title": "{}: {}={}".format(taxo["namespace"], taxo["predicate"], taxo["value"]),
                    "solution": "n/a",
                    "metadata": { "tags": [
                        "cortex",
                        results["dataType"],
                        results["analyzerName"]
                        ]
                    },
                    "type": "cortex_report",
                    "timestamp": ts,
                    "description": "Analyzer '{}' stated following taxo:\n{}={}".format(
                        taxo["namespace"], taxo["predicate"], taxo["value"])
                }
            )

    # Full report
    description = json.dumps(results["report"]["full"], indent=4)
    description_hash = hashlib.sha1(description).hexdigest()[:6]
    issues.append({
            "issue_id": len(issues)+1,
            "severity": "info", "confidence": "certain",
            "target": {
                "addr": [results["data"]],
                "protocol": results["dataType"] },
            "title": "{} full results (HASH: {})".format(
                results["analyzerName"], description_hash),
            "solution": "n/a",
            "metadata": { "tags": [
                "cortex",
                results["dataType"],
                results["analyzerName"]
                ]
            },
            "type": "cortex_report",
            "timestamp": ts,
            "description": description
        }
    )

    return issues


@app.route('/engines/cortex/getfindings/<scan_id>')
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

    findings = this.scans[scan_id]["findings"]

    summary = {
        "nb_issues": len(findings),
        "nb_info": 0,
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "engine_name": "cortex",
        "engine_version": this.scanner["version"]
    }

    # Update summary with severity counts
    for finding in findings:
        sev = finding["severity"]
        summary.update({"nb_"+sev: summary["nb_"+sev] + 1})

    scan = {
        "scan_id": scan_id,
        "assets": this.scans[scan_id]['assets'],
        "options": this.scans[scan_id]['options'],
        "status": this.scans[scan_id]['status'],
        "started_at": this.scans[scan_id]['started_at'],
        "finished_at": this.scans[scan_id]['finished_at']
    }

    # store the findings in a file
    with open(BASE_DIR+"/results/cortex_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": findings
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({ "scan": scan, "summary": summary, "issues": findings, "status": "success"})
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


@app.route('/engines/cortex/getreport/<scan_id>')
def getreport(scan_id):
    filepath = BASE_DIR+"/results/cortex_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_from_directory(BASE_DIR+"/results/", "cortex_"+scan_id+".json")


@app.route('/engines/cortex/test')
def test():
    if not APP_DEBUG:
        return jsonify({"page": "test"})

    res = "<h2>Test Page (DEBUG):</h2>"
    import urllib
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
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP, default=APP_DEBUG)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
