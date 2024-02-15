#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""URLVoid PatrOwl engine application."""

import os
import sys
import json
import time
import threading
import random
import requests
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ElementTree
from flask import Flask, request, jsonify

from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine

# from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5008
APP_MAXSCANS = int(os.environ.get("APP_MAXSCANS", 25))
APP_ENGINE_NAME = "urlvoid"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
VERSION = "1.4.26"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION,
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


@app.route("/")
def default():
    """Route by default."""
    return engine.default()


@app.route("/engines/urlvoid/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/urlvoid/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/urlvoid/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/urlvoid/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/urlvoid/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/urlvoid/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/urlvoid/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/urlvoid/status")
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route("/engines/urlvoid/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.getstatus_scan(scan_id)


@app.route("/engines/urlvoid/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/urlvoid/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route("/engines/urlvoid/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR + "/urlvoid.json"
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)

        this.keys = []
        for apikey in engine.scanner["apikeys"]:
            this.keys.append(apikey)

        del engine.scanner["apikeys"]
        engine.scanner["status"] = "READY"

    else:
        print("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}


@app.route("/engines/urlvoid/reloadconfig", methods=["GET"])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/urlvoid/startscan", methods=["POST"])
def start_scan():
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update(
            {
                "status": "error",
                "reason": "Scan refused: max concurrent active scans reached ({})".format(
                    APP_MAXSCANS
                ),
            }
        )
        return jsonify(res)

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
        return jsonify(res)

    data = json.loads(request.data)
    if "assets" not in data.keys() or "scan_id" not in data.keys():
        res.update(
            {
                "status": "refused",
                "details": {"reason": "arg error, something is missing ('assets' ?)"},
            }
        )
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, something is missing ('asset.value')",
                }
            )
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, bad value for '{}' datatype (not supported)".format(
                        asset["value"]
                    ),
                }
            )
            return jsonify(res)

        if asset["datatype"] == "url":
            parsed_uri = urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    if data["scan_id"] in engine.scans.keys():
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": "scan '{}' already launched".format(data["scan_id"]),
                },
            }
        )
        return jsonify(res)

    scan = {
        # 'assets':       data['assets'],
        "assets": assets,
        "threads": [],
        "options": data["options"],
        "scan_id": scan_id,
        "status": "STARTED",
        "started_at": int(time.time() * 1000),
        "findings": {},
    }

    engine.scans.update({scan_id: scan})
    th = threading.Thread(target=_scan_urls, args=(scan_id,))
    th.start()
    engine.scans[scan_id]["threads"].append(th)

    res.update({"status": "accepted", "details": {"scan_id": scan["scan_id"]}})

    return jsonify(res)


def _scan_urls(scan_id):
    assets = []
    for asset in engine.scans[scan_id]["assets"]:
        assets.append(asset)

    for asset in assets:
        apikey = this.keys[random.randint(0, len(this.keys) - 1)]
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            engine.scans[scan_id]["findings"][asset]["issues"] = get_report(
                asset, apikey
            )
        except Exception as ex:
            app.logger.error(
                "_scan_urls failed {}".format(
                    re.sub(r"/" + apikey + "/", r"/***/", ex.__str__())
                )
            )
            return False

    return True


def get_report(asset, apikey):
    """Get URLVoid XML report."""
    scan_url = "{}{}/host/{}/".format("http://api.urlvoid.com/api1000/", apikey, asset)
    xml = requests.get(scan_url)
    issues = []
    tree = ElementTree.fromstring(xml.text)
    if tree.find("detections/engines") is not None:
        for child in tree.find("detections/engines"):
            issues.append(child.text)

    return issues


def _parse_results(scan_id):
    issues = []
    summary = {}

    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0}
    ts = int(time.time() * 1000)

    for asset in engine.scans[scan_id]["findings"]:
        if len(engine.scans[scan_id]["findings"][asset]["issues"]) != 0:
            description = "On the host {} appear in {} identified in blacklist engines or online reputation tools :\n".format(
                asset, len(engine.scans[scan_id]["findings"][asset]["issues"])
            )
            for eng in engine.scans[scan_id]["findings"][asset]["issues"]:
                description = description + eng + "\n"
            description = (
                description
                + "For more detail go 'http://www.urlvoid.com/scan/"
                + asset
                + "/'"
            )
            nb_vulns["high"] += 1
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "high",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "http"},
                    "title": "'{}' identified in urlvoid".format(asset),
                    "solution": "n/a",
                    "metadata": {"tags": ["http"]},
                    "type": "urlvoid_report",
                    "timestamp": ts,
                    "description": description,
                }
            )
        else:
            nb_vulns["info"] += 1
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "http"},
                    "title": "'{}' have not been identified in urlvoid".format(asset),
                    "solution": "n/a",
                    "metadata": {"tags": ["http"]},
                    "type": "urlvoid_report",
                    "timestamp": ts,
                    "description": "{} have not identified in blacklist engines or online reputation tools".format(
                        asset
                    ),
                }
            )

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "urlvoid",
        "engine_version": engine.scanner["version"],
    }

    return issues, summary


@app.route("/engines/urlvoid/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    # check if the scan is finished
    status()
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update(
            {
                "status": "error",
                "reason": "scan_id '{}' not finished (status={})".format(
                    scan_id, engine.scans[scan_id]["status"]
                ),
            }
        )
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]["assets"],
        "options": engine.scans[scan_id]["options"],
        "status": engine.scans[scan_id]["status"],
        "started_at": engine.scans[scan_id]["started_at"],
        "finished_at": engine.scans[scan_id]["finished_at"],
    }

    # Store the findings in a file
    with open(
        APP_BASE_DIR + "/results/urlvoid_" + scan_id + ".json", "w"
    ) as report_file:
        json.dump(
            {"scan": scan, "summary": summary, "issues": issues},
            report_file,
            default=_json_serial,
        )

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update(
        {"scan": scan, "summary": summary, "issues": issues, "status": "success"}
    )
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR + "/results"):
        os.makedirs(APP_BASE_DIR + "/results")
    _loadconfig()


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
