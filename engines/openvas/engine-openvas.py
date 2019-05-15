#!/usr/bin/python
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

import os
import sys
import json
import time
import threading
import urlparse
from flask import Flask, request, jsonify
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions
import xml.etree.ElementTree as ET
from dns.resolver import query
from subprocess import check_output
from re import search as re_search

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = 5
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

this = sys.modules[__name__]
this.keys = []

def omp_cmd(command):
    """ This function returns the output of an 'omp' command """
    omp_cmd_base = ["omp", "-h", engine.scanner["options"]["omp_host"]["value"], "-p", engine.scanner["options"]["omp_port"]["value"], "-u", engine.scanner["options"]["omp_username"]["value"], "-w", engine.scanner["options"]["omp_password"]["value"]]
    try:
        result = check_output(omp_cmd_base + command)
    except Exception as e:
        print(e)
        result = ''
    return result

def is_ip(string):
    """ This dummy function returns True is the string is probably an IP """
    return re_search('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', string) is not None

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


@app.route('/engines/openvas/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/openvas/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/openvas/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/openvas/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/openvas/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/openvas/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/openvas/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/openvas/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/openvas/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    report_id = engine.scans[scan_id]["report_id"]
    result = omp_cmd(["--get-tasks", engine.scanner["options"]["task_id"]["value"]])
    if result == '':
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    engine.scans[scan_id]["scan_status"] = result.split(engine.scanner["options"]["task_id"]["value"])[1].split('  ')[1]

    if engine.scans[scan_id]["scan_status"] == "Done":
        res.update({"status": "FINISHED"})
        engine.scans[scan_id]["status"] = "FINISHED"
        # Get the last version of the report
        try:
            _scan_urls(scan_id)
        except Exception as e:
            res.update({"status": "error", "reason": "scan_urls did not worked ! (%s)" % e})
            return jsonify(res)
    else:
        res.update({"status": "SCANNING"})
        engine.scans[scan_id]["status"] = "SCANNING"

    return jsonify(res)


@app.route('/engines/openvas/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/openvas/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/openvas/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+'/openvas.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)

        engine.scanner['status'] = "READY"

    else:
        print "Error: config file '{}' not found".format(conf_file)
        return {"status": "error", "reason": "config file not found"}


@app.route('/engines/openvas/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route('/engines/openvas/startscan', methods=['POST'])
def start_scan():
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)

    status()
    if engine.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": engine.scanner['status']
            }})
        return jsonify(res)

    data = json.loads(request.data)
    if 'assets' not in data.keys() or 'scan_id' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update({
                "status": "error",
                "reason": "arg error, something is missing ('asset.value')"
            })
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update({
                "status": "error",
                "reason": "arg error, bad value for '{}' datatype (not supported)".format(asset["value"])
            })
            return jsonify(res)

        if asset["datatype"] == "url":
            parsed_uri = urlparse.urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        assets.append(asset["value"])

    scan_id = str(data['scan_id'])

    if data['scan_id'] in engine.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' already launched".format(data['scan_id']),
            }
        })
        return jsonify(res)

    scan = {
        'assets':       assets,
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'lock':         False,
        'started_at':   int(time.time() * 1000),
        'findings':     {}
    }

    scan["report_id"] = omp_cmd(["--start-task", engine.scanner["options"]["task_id"]["value"]]).split("\n")[0]

    if scan["report_id"] == '':
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' already launched".format(data['scan_id']),
            }
        })
        return jsonify(res)

    engine.scans.update({scan_id: scan})
    thread = threading.Thread(target=_scan_urls, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]['threads'].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan_urls(scan_id):
    # Is it locked ?
    if engine.scans[scan_id]["lock"]:
        print("locked")
        return True

    # Does the scan is terminated ?
    if "scan_status" in engine.scans[scan_id].keys():
        scan_status = engine.scans[scan_id]["scan_status"]
    else:
        return True
    if scan_status != "Done":
        return True

    engine.scans[scan_id]["lock"] = True
    print("lock on")

    assets = []
    for asset in engine.scans[scan_id]['assets']:
        assets.append(asset)

    for asset in assets:
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            engine.scans[scan_id]["findings"][asset]['issues'] = get_report(asset, scan_id)
        except Exception as e:
            print "_scan_urls: API Connexion error (quota?)"
            print e
            return False

    print("lock off")
    engine.scans[scan_id]["lock"] = False
    return True


def get_report(asset, scan_id):
    """Get report."""

    report_id = engine.scans[scan_id]["report_id"]
    issues = []

    if not os.path.isfile('results/openvas_report_%s.xml' % scan_id):
        result = omp_cmd(["--get-report", report_id])
        result_file = open("results/openvas_report_%s.xml" % scan_id, "w")
        result_file.write(result)
        result_file.close()

    try:
        tree = ET.parse("results/openvas_report_%s.xml" % scan_id)
    except Exception:
        # No Element found in XML file
        return {"status": "ERROR", "reason": "no issues found"}

    if is_ip(asset):
        resolved_asset_ip = asset
    else:
        # Let's suppose it's a fqdn then...
        try:
            resolved_asset_ip = query(asset).response.answer[0].to_text().split(" ")[-1]
        except Exception as e:
            # What is that thing ?
            return issues

    report = tree.getroot().find("report")
    for result in report.find("results").findall("result"):
        host_ip = result.find("host").text
        severity = result.find("severity").text
        cve = result.find("nvt").find("cve").text
        threat = result.find("threat").text
        if resolved_asset_ip == host_ip:
            issues.append([severity, cve, threat])

    return issues


def _parse_results(scan_id):
    while engine.scans[scan_id]["lock"]:
        print("report is not terminated yet, going to sleep")
        time.sleep(10)

    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    timestamp = int(time.time() * 1000)
    report_id = engine.scans[scan_id]["report_id"]

    for asset in engine.scans[scan_id]["findings"]:
        if engine.scans[scan_id]["findings"][asset]["issues"]:
            description = ''
            cvss_max = float(0)
            for eng in engine.scans[scan_id]["findings"][asset]["issues"]:
                if float(eng[0]) > 0:
                    cvss_max = max(float(eng[0]), cvss_max)
                    description = description + "[%s] CVSS: %s - Associated CVE : %s" % (eng[2], eng[0], eng[1]) + "\n"
            description = description + "For more detail go to 'https://%s/omp?cmd=get_report&report_id=%s'" % (engine.scanner["options"]["omp_host"]["value"], report_id)

            criticity = "high"
            if cvss_max == 0:
                criticity = "info"
            elif cvss_max < 4.0:
                criticity = "low"
            elif cvss_max < 7.0:
                criticity = "medium"

            nb_vulns[criticity] += 1

            issues.append({
                "issue_id": len(issues)+1,
                "severity": criticity, "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "'{}' identified in openvas".format(asset),
                "solution": "n/a",
                "metadata": {},
                "type": "openvas_report",
                "timestamp": timestamp,
                "description": description,
            })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "openvas",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route('/engines/openvas/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    status()
    if engine.scans[scan_id]['status'] != "FINISHED":
        res.update({"status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]['status'])})
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]['assets'],
        "options": engine.scans[scan_id]['options'],
        "status": engine.scans[scan_id]['status'],
        "started_at": engine.scans[scan_id]['started_at'],
        "finished_at": engine.scans[scan_id]['finished_at']
    }

    # Store the findings in a file
    with open(APP_BASE_DIR+"/results/openvas_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({"scan": scan, "summary": summary, "issues": issues, "status": "success"})
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
