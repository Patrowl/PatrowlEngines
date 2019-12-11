#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyeWitness PatrOwl engine application."""

from json import dump, load, loads
from logging import getLogger
from os import makedirs, listdir, walk
from os.path import dirname, exists, realpath
from re import search
from subprocess import check_output, CalledProcessError, STDOUT
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
LOG = getLogger("werkzeug")

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


def eyewitness_cmd(list_url, asset_id, scan_id, extra_opts=[]):
    """
    Returns the screenshot path
    """
    if 'extra_opts' in extra_opts:
        extra_opts = extra_opts['extra_opts'].split(' ')
    else:
        extra_opts = []
    result = dict()
    base_path = engine.scanner["options"]["ScreenshotsDirectory"]["value"] + scan_id
    asset_base_path = base_path + "/" + str(asset_id)
    if not exists(base_path):
        makedirs(base_path, mode=0o755)
    if not exists(asset_base_path):
        makedirs(asset_base_path, mode=0o755)
    count = 0
    for url in list_url:
        screenshot_base_path = asset_base_path + "/" + str(count)
        try:
            check_output(["{}/EyeWitness.py".format(engine.scanner["options"]["EyeWitnessDirectory"]["value"]), "--single", url, "--web", "-d", screenshot_base_path, "--no-prompt"] + extra_opts)
        except:
            continue 
        screenshot_files = listdir(screenshot_base_path + "/screens")
        # Retry screenshot capture if previous fail
        if not screenshot_files:
            try:
                check_output(["{}/EyeWitness.py".format(engine.scanner["options"]["EyeWitnessDirectory"]["value"]), "--single", url, "--web", "-d", screenshot_base_path, "--no-prompt"] + extra_opts)
            except:
                continue
        if not screenshot_files:
            continue
        result_url = "{repo_url}/{scan_id}/{asset_id}/{count}/screens/{screenshot}".format(repo_url=engine.scanner["options"]["ScreenshotsURL"]["value"], scan_id=scan_id, asset_id=asset_id, count=count, screenshot=screenshot_files[0])
        result.update({url: {"path": "{}/screens/{}".format(screenshot_base_path, screenshot_files[0]), "url": result_url}})
        count += 1
    return result


def get_last_screenshot(current_path, asset_id, scan_id):
    """
    Returns the path and the URL of the last screenshot taken
    """
    last_scan_id = 0
    last_scan_path = current_path
    last_scan_url = ''
    for root, dirs, files in walk(engine.scanner["options"]["ScreenshotsDirectory"]["value"]):
        if current_path.split("/")[-1] in files:
            _scan_id = int(root.split("/")[4])
            # Get the latest scan_id valid
            if _scan_id < int(scan_id) and _scan_id >= last_scan_id:
                last_scan_id = _scan_id
                last_scan_path = "{}/{}".format(root, current_path.split("/")[-1])

    last_scan_url = "{repo_url}/{scan_id}/{asset_id}/{count}/screens/{screenshot}".format(repo_url=engine.scanner["options"]["ScreenshotsURL"]["value"], scan_id=last_scan_id, asset_id=asset_id, count=last_scan_path.split("/")[6], screenshot=last_scan_path.split("/")[-1])

    return last_scan_path, last_scan_url

def diff_screenshot(screenshot1, screenshot2):
    """
    Returns the percentage of differences between screenshot & screenshot2
    """
    try:
        output = check_output([engine.scanner["options"]["ImageMagickComparePath"]["value"], "-metric", "RMSE", screenshot1, screenshot2, "NULL:"], stderr=STDOUT)
    except CalledProcessError as e:
        output = e.output
        returncode = e.returncode
    except ValueError:
        return None

    try:
        diff = search("(\((.*?)\))", str(output))
        percent_diff = int(float(diff.group(2)) * 100)
    except AttributeError:
        return None

    return percent_diff


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    LOG.debug(e)
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
        LOG.error("Error: EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory))
        return jsonify({"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory)})

    ScreenshotsDirectory = engine.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(ScreenshotsDirectory):
        LOG.error("Error: ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory))
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory)}

    ImageMagickComparePath = engine.scanner["options"]["ImageMagickComparePath"]["value"]
    if not exists(ImageMagickComparePath):
        LOG.error("Error: ImageMagickComparePath not found : {}".format(ImageMagickComparePath))
        return {"status": "error", "reason": "ImageMagickComparePath not found : {}".format(ImageMagickComparePath)}

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
        LOG.error("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}

    if "EyeWitnessDirectory" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify EyeWitnessDirectory in options")
        return {"status": "error", "reason": "You have to specify EyeWitnessDirectory in options"}

    EyeWitnessDirectory = engine.scanner["options"]["EyeWitnessDirectory"]["value"]
    if not exists(EyeWitnessDirectory):
        LOG.error("Error: EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory))
        return {"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(EyeWitnessDirectory)}

    LOG.info("[OK] EyeWitnessDirectory")

    if "ScreenshotsURL" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify ScreenshotsURL in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsURL in options"}

    if "ScreenshotsDirectory" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify ScreenshotsDirectory in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsDirectory in options"}

    ScreenshotsDirectory = engine.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(ScreenshotsDirectory):
        LOG.error("Error: ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory))
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(ScreenshotsDirectory)}

    LOG.info("[OK] ScreenshotsDirectory")


    if "ImageMagickComparePath" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify ImageMagickComparePath in options")
        return {"status": "error", "reason": "You have to specify ImageMagickComparePath in options"}
    ImageMagickComparePath = engine.scanner["options"]["ImageMagickComparePath"]["value"]
    if not exists(ImageMagickComparePath):
        LOG.error("Error: ImageMagickComparePath not found : {}".format(ImageMagickComparePath))
        return {"status": "error", "reason": "ImageMagickComparePath not found : {}".format(ImageMagickComparePath)}

    LOG.info("[OK] ImageMagickComparePath")


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
        LOG.debug("locked")
        return True

    engine.scans[scan_id]["lock"] = True
    LOG.debug("lock on")

    assets = []
    for asset in engine.scans[scan_id]["assets"]:
        assets.append(asset)

    for asset in assets:
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            asset_data = next((x for x in engine.scans[scan_id]["assets_data"] if x["value"] == asset), None)
            urls = list()
            if asset.startswith("http://"):
                urls.append("http://"+asset)
            elif asset.startswith("https://"):
                urls.append("https://"+asset)
            else:
                # Check both
                urls.append("http://"+asset)
                urls.append("https://"+asset)

            result = eyewitness_cmd(urls, asset_data["id"], scan_id, extra_opts=engine.scans[scan_id]['options'])

            # Get differences with the last screenshot
            for url in result:
                last_screenshot_path, last_screenshot_url = get_last_screenshot(result[url]["path"], asset_data["id"], scan_id)
                result[url].update({"previous_diff": diff_screenshot(result[url]["path"], last_screenshot_path), "last_screenshot_path": last_screenshot_path, "last_screenshot_url": last_screenshot_url})

            # Get the difference between the current screenshots
            current_diff = None
            if len(result) == 2:
                current_diff = diff_screenshot(result[urls[0]]["path"], result[urls[1]]["path"])
            result["current_diff"] = current_diff

            engine.scans[scan_id]["findings"][asset]["issues"] = result
        except Exception as e:
            LOG.error("_scan_urls: API Connexion error for asset {}: {}".format(asset, e))
            return False

    LOG.debug("lock off")
    engine.scans[scan_id]["lock"] = False
    return True


def _parse_results(scan_id):
    while engine.scans[scan_id]["lock"]:
        LOG.debug("report is not terminated yet, going to sleep")
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
            asset_issues = engine.scans[scan_id]["findings"][asset]["issues"]
            screenshot_urls = list()
            if not asset_issues:
                screenshot_urls = "No screenshots available"
            for url in asset_issues:
                if url == "current_diff":
                    continue
                screenshot_urls.append(asset_issues[url]["url"])
                # Create an issue if the screenshot differs from last time
                previous_diff = asset_issues[url]["previous_diff"]
                if previous_diff is None:
                    nb_vulns[get_criticity(cvss_max)] += 1
                    issues.append({
                        "issue_id": len(issues)+1,
                        "severity": get_criticity(0), "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "http"},
                        "title": "[{}] Screenshot differs from last time".format(timestamp),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}, "links": [asset_issues[url]["url"], asset_issues[url]["last_screenshot_url"]]},
                        "type": "eyewitness_screenshot_diff",
                        "timestamp": timestamp,
                        "description": "Too much differences"
                    })
                elif previous_diff >= 20:
                    nb_vulns[get_criticity(cvss_max)] += 1
                    issues.append({
                        "issue_id": len(issues)+1,
                        "severity": get_criticity(0), "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "http"},
                        "title": "[{}] Screenshot differs from last time".format(timestamp),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}, "links": [asset_issues[url]["url"], asset_issues[url]["last_screenshot_url"]]},
                        "type": "eyewitness_screenshot_diff",
                        "timestamp": timestamp,
                        "description": "The difference is about {}%".format(previous_diff)
                    })

            current_diff = "These screeshots are different"
            if asset_issues["current_diff"] is not None:
                current_diff = "The diffence between these screenshots is {}%".format(asset_issues["current_diff"])
            nb_vulns[get_criticity(cvss_max)] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": get_criticity(cvss_max), "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "[{}] Some domain has been screenshoted by eyewitness".format(timestamp),
                "solution": "n/a",
                "metadata": {"risk": {"cvss_base_score": cvss_max}, "links": screenshot_urls},
                "type": "eyewitness_screenshot",
                "timestamp": timestamp,
                "description": "Screenshots: {}, Current Diff: {}".format(screenshot_urls, current_diff)
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
    LOG.debug("Run engine")


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
