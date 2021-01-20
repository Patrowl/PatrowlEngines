# -*- coding: utf-8 -*-
"""owl_request PatrOwl engine application."""

import os
import sys
import json
import time
import copy
import datetime
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5019
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 25))
APP_ENGINE_NAME = "owl_request"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
VERSION = "1.4.18"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)

this = sys.modules[__name__]
this.keys = []


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


@app.route('/engines/owl_request/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/owl_request/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/owl_request/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/owl_request/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/owl_request/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/owl_request/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/owl_request/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/owl_request/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/owl_request/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.getstatus_scan(scan_id)


@app.route('/engines/owl_request/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/owl_request/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/owl_request/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+'/owl_request.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)

        engine.scanner['status'] = "READY"

    else:
        print("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}


@app.route('/engines/owl_request/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route('/engines/owl_request/startscan', methods=['POST'])
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

    scan = {}
    data = json.loads(request.data)

    if 'assets' not in data.keys() or 'scan_id' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        return jsonify(res)

    # Check assets
    if 'assets' not in data.keys() or 'scan_id' not in data.keys():
        res.update({
            "status": "refused",
            "reason": "arg error, something is missing (ex: 'assets', 'scan_id')"
        })
        return jsonify(res)

    valid_assets = copy.deepcopy(data["assets"])
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            valid_assets.remove(asset)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            valid_assets.remove(asset)

        # url transform
        if asset["datatype"] == 'url':
            valid_assets.remove(asset)
            valid_assets.append({
                "id": asset["id"],
                "datatype": asset["datatype"],
                "criticity": asset["criticity"],
                "value": "{uri.netloc}".format(uri=urlparse(asset["value"]))
            })

    # Check scan_id
    scan["scan_id"] = str(data["scan_id"])
    if data["scan_id"] in engine.scans.keys():
        res.update({"status": "error", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    scan["assets"] = []
    for asset in valid_assets:
        if asset["value"] not in [h["host"] for h in scan["assets"]]:
            target_host = asset["value"]
            target_url = "{}analyze?host={}&port={}&publish=off&ignoreMismatch=on&maxAge=2&fromCache=on".format(engine.scanner['api_url'], target_host, scan["target_port"])
            scan["assets"].append({"host": target_host, "url": target_url})

    scan["started_at"] = datetime.datetime.now()
    scan["status"] = "STARTED"
    scan["threads"] = []
    scan["findings"] = []

    engine.scans.update({scan["scan_id"]: scan})
    # thread = threading.Thread(target=_scan_urls, args=(scan["scan_id"],))
    # thread.start()
    # engine.scans[scan["scan_id"]]['threads'].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan_http(scan_id, asset):
    # Initialize findings storage if needed
    if asset not in engine.scans[scan_id]:
        engine.scans[scan_id][asset] = {}

    if "findings" not in engine.scans[scan_id][asset]:
        engine.scans[scan_id][asset]["findings"] = {}

    http_method = engine.scans[scan_id]["options"]["http"]["method"]
    print(http_method)

    url = asset
    print(url)

    http_data = {}

    try:
        if http_method == "GET":
            requests.get(url)
        elif http_method == "POST":
            requests.post(url, data=http_data)
        elif http_method == "PUT":
            requests.put(url, data=http_data)
        elif http_method == "DELETE":
            requests.delete(url)
        elif http_method == "HEAD":
            requests.head(url)
        elif http_method == "PATCH":
            requests.patch(url, data=http_data)
        elif http_method == "OPTIONS":
            requests.options(url)
    except Exception as e:
        print(e)
        return False

    return True


def _parse_results(scan_id):
    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    timestamp = int(time.time() * 1000)

    for asset in engine.scans[scan_id]["findings"]:
        if engine.scans[scan_id]["findings"][asset]["issues"]:
            description = "On the host {} appear in {} identified in blacklist engines or online reputation tools :\n".format(asset, len(engine.scans[scan_id]["findings"][asset]["issues"]))
            for eng in engine.scans[scan_id]["findings"][asset]["issues"]:
                description = description + eng + "\n"
            description = description + "For more detail go 'http://www.owl_request.com/scan/" + asset + "/'"
            nb_vulns["high"] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "high", "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "'{}' identified in owl_request".format(asset),
                "solution": "n/a",
                "metadata": {"tags": ["http"]},
                "type": "owl_request_report",
                "timestamp": timestamp,
                "description": description
            })
        else:
            nb_vulns["info"] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "'{}' have not been identified in owl_request".format(asset),
                "solution": "n/a",
                "metadata": {"tags": ["http"]},
                "type": "owl_request_report",
                "timestamp": timestamp,
                "description": "{} have not identified in blacklist engines or online reputation tools".format(asset)
            })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "owl_request",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route('/engines/owl_request/getfindings/<scan_id>', methods=['GET'])
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
    with open(APP_BASE_DIR+"/results/owl_request_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"})
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
