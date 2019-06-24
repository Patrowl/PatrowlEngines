#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyeWitness PatrOwl engine application."""

from __future__ import absolute_import

from os import makedirs, listdir
from os.path import dirname, exists, realpath
from json import dump, load, loads
from subprocess import check_output
from threading import Thread
from time import time, sleep
from urllib.parse import urlparse

# Third party library imports
from flask import Flask, request, jsonify

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5018
APP_MAXSCANS = 5
APP_ENGINE_NAME = "eyewitness"
APP_BASE_DIR = dirname(realpath(__file__))

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)


def get_criticity(score):
    """Return the level of criicity."""
    criticity = "high"
    if score == 0:
        criticity = "info"
    elif score < 4.0:
        criticity = "low"
    elif score < 7.0:
        criticity = "medium"
    return criticity


def eyewitness_cmd(url, asset_id, scan_id):
    """Return the screenshot path."""
    base_path = engine.scanner["options"]["ScreenshotsDirectory"]["value"] + scan_id
    if not exists(base_path):
        makedirs(base_path, mode=0o755)
    asset_path = base_path + "/" + str(asset_id)
    check_output([
        "{}/EyeWitness.py".format(
            engine.scanner["options"]["EyeWitnessDirectory"]["value"]),
        "--single", url,
        "--web",
        "-d", asset_path,
        "--no-prompt",
        "--prepend-https"])
    screens_path = asset_path + "/screens"
    screenshot_files = listdir(screens_path)
    if not screenshot_files:
        return list()
    result_url = "{repo_url}/{scan_id}/{asset_id}/screens/{screenshot}".format(
        repo_url=engine.scanner["options"]["ScreenshotsURL"]["value"],
        scan_id=scan_id,
        asset_id=asset_id,
        screenshot=screenshot_files[0])
    return result_url


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    print(e)
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


@app.route("/engines/eyewitness/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/eyewitness/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/eyewitness/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/eyewitness/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/eyewitness/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/eyewitness/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/eyewitness/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/eyewitness/status")
def status():
    """Get status on engine and all scans."""
    EyeWitnessDirectory = engine.scanner["options"]["EyeWitnessDirectory"]["value"]
    if not exists(EyeWitnessDirectory):
        print("Error: EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory))
        return jsonify({"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory)})

    ScreenshotsDirectory = engine.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(ScreenshotsDirectory):
        print("Error: ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory))
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory)}

    return engine.getstatus()


@app.route("/engines/eyewitness/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    if engine.scans[scan_id]["lock"]:
        res.update({"status": "SCANNING"})
        engine.scans[scan_id]["status"] = "SCANNING"
    else:
        res.update({"status": "FINISHED"})
        engine.scans[scan_id]["status"] = "FINISHED"

    return jsonify(res)


@app.route("/engines/eyewitness/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/eyewitness/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route("/engines/eyewitness/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+"/eyewitness.json"
    if exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = load(json_data)
        engine.scanner["status"] = "READY"
    else:
        print("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}

    if "EyeWitnessDirectory" not in engine.scanner["options"]:
        print("Error: You have to specify EyeWitnessDirectory in options")
        return {"status": "error", "reason": "You have to specify EyeWitnessDirectory in options"}

    EyeWitnessDirectory = engine.scanner["options"]["EyeWitnessDirectory"]["value"]
    if not exists(EyeWitnessDirectory):
        print("Error: EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory))
        return {"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory)}

    print("[OK] EyeWitnessDirectory")

    if "ScreenshotsURL" not in engine.scanner["options"]:
        print("Error: You have to specify ScreenshotsURL in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsURL in options"}

    if "ScreenshotsDirectory" not in engine.scanner["options"]:
        print("Error: You have to specify ScreenshotsDirectory in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsDirectory in options"}

    ScreenshotsDirectory = engine.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(ScreenshotsDirectory):
        print("Error: ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory))
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory)}

    print("[OK] ScreenshotsDirectory")

@app.route("/engines/eyewitness/reloadconfig", methods=["GET"])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/eyewitness/startscan", methods=["POST"])
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
    if engine.scanner["status"] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": engine.scanner["status"]
            }})
        return jsonify(res)

    data = loads(request.data.decode("utf-8"))
    if "assets" not in data.keys() or "scan_id" not in data.keys():
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
            parsed_uri = urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    if data["scan_id"] in engine.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' is probably already launched".format(data["scan_id"]),
            }
        })
        return jsonify(res)

    scan = {
        "assets":       assets,
        "assets_data":  data["assets"],
        "threads":      [],
        "options":      data["options"],
        "scan_id":      scan_id,
        "status":       "STARTED",
        "lock":         False,
        "started_at":   int(time() * 1000),
        "findings":     {}
    }

    engine.scans.update({scan_id: scan})
    thread = Thread(target=_scan_urls, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]["threads"].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan["scan_id"]
        }
    })

    return jsonify(res)


def _scan_urls(scan_id):
    # Is it locked ?
    if engine.scans[scan_id]["lock"]:
        print("locked")
        return True

    engine.scans[scan_id]["lock"] = True
    print("lock on")

    assets = []
    for asset in engine.scans[scan_id]["assets"]:
        assets.append(asset)

    for asset in assets:
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            asset_data = next((x for x in engine.scans[scan_id]["assets_data"] if x["value"] == asset), None)
            engine.scans[scan_id]["findings"][asset]["issues"] = eyewitness_cmd(asset, asset_data["id"], scan_id)
        except Exception as e:
            print("_scan_urls: API Connexion error for asset {}".format(asset))
            print(e)
            return False

    print("lock off")
    engine.scans[scan_id]["lock"] = False
    return True

def _parse_results(scan_id):
    while engine.scans[scan_id]["lock"]:
        print("report is not terminated yet, going to sleep")
        sleep(10)

    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    timestamp = int(time() * 1000)

    for asset in engine.scans[scan_id]["findings"]:
        cvss_max = float(0)
        if engine.scans[scan_id]["findings"][asset]["issues"]:
            screenshot_url = engine.scans[scan_id]["findings"][asset]["issues"]
            if not screenshot_url:
                screenshot_url = "No screenshot available"
            nb_vulns[get_criticity(cvss_max)] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": get_criticity(cvss_max), "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "[{}] Some domain has been screenshoted by eyewitness".format(timestamp),
                "solution": "n/a",
                "metadata": {"risk": {"cvss_base_score": cvss_max}, "links": [screenshot_url]},
                "type": "eyewitness_screenshot",
                "timestamp": timestamp,
                "description": screenshot_url
            })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "eyewitness",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route("/engines/eyewitness/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    status()
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update({"status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]["status"])})
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]["assets"],
        "options": engine.scans[scan_id]["options"],
        "status": engine.scans[scan_id]["status"],
        "started_at": engine.scans[scan_id]["started_at"],
        "finished_at": engine.scans[scan_id]["finished_at"]
    }

    # Store the findings in a file
    with open(APP_BASE_DIR+"/results/eyewitness_"+scan_id+".json", "w") as report_file:
        dump({
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
    if not exists(APP_BASE_DIR+"/results"):
        makedirs(APP_BASE_DIR+"/results")
    _loadconfig()
    print("Run engine")


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
