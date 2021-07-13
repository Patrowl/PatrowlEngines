#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EyeWitness PatrOwl engine application.

Copyright (C) 2021 Nicolas Mattiocco - @MaKyOtOx
Licensed under the AGPLv3 License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from datetime import datetime
from json import dump, load, loads
from logging import getLogger
import os
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
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 25))
APP_ENGINE_NAME = "eyewitness"
APP_BASE_DIR = dirname(realpath(__file__))
COMPARE_CEIL = 25
LOG = getLogger("werkzeug")
VERSION = "1.4.18"

ENGINE = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)


def get_options(payload):
    """Extract formatted options from the payload."""
    options = dict()
    user_opts = payload["options"]
    if isinstance(user_opts, str):
        user_opts = loads(user_opts)
    if "extra_opts" in user_opts:
        options["extra_opts"] = user_opts["extra_opts"]
    return options


def get_criticity(score):
    """Return the level of criticity."""
    criticity = "high"
    if score == 0:
        criticity = "info"
    elif score < 4.0:
        criticity = "low"
    elif score < 7.0:
        criticity = "medium"
    return criticity


def eyewitness_cmd(list_url, asset_id, scan_id, extra_opts):
    """Return the screenshot path."""
    if 'extra_opts' in extra_opts:
        extra_opts = extra_opts['extra_opts'].split(' ')
    else:
        extra_opts = []
    result = dict()
    base_path = ENGINE.scanner["options"]["ScreenshotsDirectory"]["value"] + scan_id
    asset_base_path = base_path + "/" + str(asset_id)
    if not exists(base_path):
        os.makedirs(base_path, mode=0o755)
    if not exists(asset_base_path):
        os.makedirs(asset_base_path, mode=0o755)
    count = 0
    for url in list_url:
        screenshot_base_path = asset_base_path + "/" + str(count)
        try:
            check_output(["{}/EyeWitness.py".format(ENGINE.scanner["options"]["EyeWitnessDirectory"]["value"]), "--single", url, "--web", "-d", screenshot_base_path, "--no-prompt"] + extra_opts)
        except Exception as err_msg:
            LOG.warning(err_msg)
            continue
        screenshot_files = os.listdir(screenshot_base_path + "/screens")
        # Retry screenshot capture if previous fail
        if not screenshot_files:
            try:
                check_output(["{}/EyeWitness.py".format(ENGINE.scanner["options"]["EyeWitnessDirectory"]["value"]), "--single", url, "--web", "-d", screenshot_base_path, "--no-prompt"] + extra_opts)
            except Exception as err_msg:
                LOG.warning(err_msg)
                continue
        if not screenshot_files:
            continue
        result_url = "{repo_url}/{scan_id}/{asset_id}/{count}/screens/{screenshot}".format(repo_url=ENGINE.scanner["options"]["ScreenshotsURL"]["value"], scan_id=scan_id, asset_id=asset_id, count=count, screenshot=screenshot_files[0])
        report_url = "{repo_url}/{scan_id}/{asset_id}/{count}/report.html".format(repo_url=ENGINE.scanner["options"]["ScreenshotsURL"]["value"], scan_id=scan_id, asset_id=asset_id, count=count)
        report_sources_path = "{base_path}/{asset_id}/{count}/source/".format(base_path=base_path, asset_id=asset_id, count=count)
        result.update({url: {
            "path": "{}/screens/{}".format(screenshot_base_path, screenshot_files[0]),
            "url": result_url,
            "report": report_url,
            "report_sources_path": report_sources_path}})
        count += 1
    return result


def get_last_screenshot(current_path, asset_id, scan_id):
    """Return the path and the URL of the last screenshot taken."""
    last_scan_id = 0
    last_scan_path = current_path
    last_scan_url = ''
    for root, _, files in os.walk(ENGINE.scanner["options"]["ScreenshotsDirectory"]["value"]):
        if current_path.split("/")[-1] in files:
            _scan_id = int(root.split("/")[4])
            # Get the latest scan_id valid
            if int(scan_id) > _scan_id >= last_scan_id:
                last_scan_id = _scan_id
                last_scan_path = "{}/{}".format(root, current_path.split("/")[-1])

    last_scan_url = "{repo_url}/{scan_id}/{asset_id}/{count}/screens/{screenshot}".format(repo_url=ENGINE.scanner["options"]["ScreenshotsURL"]["value"], scan_id=last_scan_id, asset_id=asset_id, count=last_scan_path.split("/")[6], screenshot=last_scan_path.split("/")[-1])

    return last_scan_path, last_scan_url


def diff_screenshot(screenshot1, screenshot2):
    """Return the percentage of differences between 2 screenshots."""
    try:
        output = check_output([ENGINE.scanner["options"]["ImageMagickComparePath"]["value"], "-metric", "RMSE", screenshot1, screenshot2, "NULL:"], stderr=STDOUT)
    except CalledProcessError as err_msg:
        output = err_msg.output
    except ValueError:
        return None

    try:
        diff = search("(\((.*?)\))", str(output))
        percent_diff = int(float(diff.group(2)) * 100)
    except AttributeError:
        return None

    return percent_diff


def is_forsale(report_sources_path):
    """Return True if domain is for sale."""
    if not exists(report_sources_path) or \
        not os.listdir(report_sources_path) or \
        "RulesForSale" not in ENGINE.scanner["options"]:
        return False
    report_file_path = report_sources_path + os.listdir(report_sources_path)[0]
    report_file = open(report_file_path, 'r')
    report_content = report_file.read()
    report_file.close()
    for rule_name in ENGINE.scanner["options"]["RulesForSale"]:
        for rule_value in ENGINE.scanner["options"]["RulesForSale"][rule_name]:
            if rule_value in report_content:
                LOG.warning("Match: %s rule", rule_name)
                return True
    return False


@app.errorhandler(404)
def page_not_found(error):
    """Page not found."""
    return ENGINE.page_not_found()


@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    """Invalid request usage."""
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response


@app.route("/")
def default():
    """Route by default."""
    return ENGINE.default()


@app.route("/engines/eyewitness/")
def index():
    """Return index page."""
    return ENGINE.index()


@app.route("/engines/eyewitness/liveness")
def liveness():
    """Return liveness page."""
    return ENGINE.liveness()


@app.route("/engines/eyewitness/readiness")
def readiness():
    """Return readiness page."""
    return ENGINE.readiness()


@app.route("/engines/eyewitness/test")
def test():
    """Return test page."""
    return ENGINE.test()


@app.route("/engines/eyewitness/info")
def info():
    """Get info on running ENGINE."""
    return ENGINE.info()


@app.route("/engines/eyewitness/clean")
def clean():
    """Clean all scans."""
    return ENGINE.clean()


@app.route("/engines/eyewitness/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return ENGINE.clean_scan(scan_id)


@app.route("/engines/eyewitness/status")
def status():
    """Get status on engine and all scans."""
    eyewitness_directory = ENGINE.scanner["options"]["EyeWitnessDirectory"]["value"]
    if not exists(eyewitness_directory):
        LOG.error("Error: EyeWitnessDirectory not found : %s", eyewitness_directory)
        return jsonify({"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(eyewitness_directory)})

    screenshots_directory = ENGINE.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(screenshots_directory):
        LOG.error("Error: ScreenshotsDirectory not found : %s", screenshots_directory)
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(screenshots_directory)}

    imagemagick_compare_path = ENGINE.scanner["options"]["ImageMagickComparePath"]["value"]
    if not exists(imagemagick_compare_path):
        LOG.error("Error: ImageMagickComparePath not found : %s", imagemagick_compare_path)
        return {"status": "error", "reason": "ImageMagickComparePath not found : {}".format(imagemagick_compare_path)}

    return ENGINE.getstatus()


@app.route("/engines/eyewitness/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in ENGINE.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        LOG.warning(res)
        return jsonify(res)

    if ENGINE.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        LOG.warning(res)
        return jsonify(res)

    if ENGINE.scans[scan_id]["lock"]:
        res.update({"status": "SCANNING"})
        ENGINE.scans[scan_id]["status"] = "SCANNING"
    else:
        res.update({"status": "FINISHED"})
        ENGINE.scans[scan_id]["status"] = "FINISHED"

    return jsonify(res)


@app.route("/engines/eyewitness/stopscans")
def stop():
    """Stop all scans."""
    return ENGINE.stop()


@app.route("/engines/eyewitness/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return ENGINE.stop_scan(scan_id)


@app.route("/engines/eyewitness/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return ENGINE.getreport(scan_id)


def _loadconfig():
    """Load config during startup."""
    conf_file = APP_BASE_DIR+"/eyewitness.json"
    if exists(conf_file):
        json_data = open(conf_file)
        ENGINE.scanner = load(json_data)
        ENGINE.scanner["status"] = "READY"
    else:
        LOG.error("Error: config file '%s' not found", conf_file)
        return {"status": "error", "reason": "config file not found"}

    if "EyeWitnessDirectory" not in ENGINE.scanner["options"]:
        LOG.error("Error: You have to specify EyeWitnessDirectory in options")
        return {"status": "error", "reason": "You have to specify EyeWitnessDirectory in options"}

    eyewitness_directory = ENGINE.scanner["options"]["EyeWitnessDirectory"]["value"]
    if not exists(eyewitness_directory):
        LOG.error("Error: EyeWitnessDirectory not found : %s", eyewitness_directory)
        return {"status": "error", "reason": "EyeWitnessDirectory not found : {}".format(eyewitness_directory)}

    LOG.warning("[OK] EyeWitnessDirectory")

    if "ScreenshotsURL" not in ENGINE.scanner["options"]:
        LOG.error("Error: You have to specify ScreenshotsURL in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsURL in options"}

    if "ScreenshotsDirectory" not in ENGINE.scanner["options"]:
        LOG.error("Error: You have to specify ScreenshotsDirectory in options")
        return {"status": "error", "reason": "You have to specify ScreenshotsDirectory in options"}

    screenshots_directory = ENGINE.scanner["options"]["ScreenshotsDirectory"]["value"]
    if not exists(screenshots_directory):
        LOG.error("Error: ScreenshotsDirectory not found : %s", screenshots_directory)
        return {"status": "error", "reason": "ScreenshotsDirectory not found : {}".format(screenshots_directory)}

    LOG.warning("[OK] ScreenshotsDirectory")


    if "ImageMagickComparePath" not in ENGINE.scanner["options"]:
        LOG.error("Error: You have to specify ImageMagickComparePath in options")
        return {"status": "error", "reason": "You have to specify ImageMagickComparePath in options"}
    imagemagick_compare_path = ENGINE.scanner["options"]["ImageMagickComparePath"]["value"]
    if not exists(imagemagick_compare_path):
        LOG.error("Error: ImageMagickComparePath not found : %s", imagemagick_compare_path)
        return {"status": "error", "reason": "ImageMagickComparePath not found : {}".format(imagemagick_compare_path)}

    LOG.warning("[OK] ImageMagickComparePath")

    if "RulesForSale" not in ENGINE.scanner["options"]:
        LOG.warning("Warning: You have to specify RulesForSale in options")
    else:
        ENGINE.scanner["options"]["RulesForSale"]
        LOG.warning("[OK] RulesForSale")


@app.route("/engines/eyewitness/reloadconfig", methods=["GET"])
def reloadconfig():
    """Reload config."""
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": ENGINE.scanner})
    LOG.warning(res)
    return jsonify(res)


@app.route("/engines/eyewitness/startscan", methods=["POST"])
def start_scan():
    """Start scan function."""
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(ENGINE.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        LOG.warning(res)
        return jsonify(res)

    status()
    if ENGINE.scanner["status"] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": ENGINE.scanner["status"]
            }})
        LOG.warning(res)
        return jsonify(res)

    data = loads(request.data.decode("utf-8"))
    if "assets" not in data.keys() or "scan_id" not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        LOG.warning(res)
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update({
                "status": "error",
                "reason": "arg error, something is missing ('asset.value')"
            })
            LOG.warning(res)
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in ENGINE.scanner["allowed_asset_types"]:
            res.update({
                "status": "error",
                "reason": "arg error, bad value for '{}' datatype (not supported)".format(asset["value"])
            })
            LOG.warning(res)
            return jsonify(res)

        if asset["datatype"] == "url":
            parsed_uri = urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        if asset["value"] not in assets:
            assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    if data["scan_id"] in ENGINE.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' is probably already launched".format(data["scan_id"]),
            }
        })
        LOG.warning(res)
        return jsonify(res)

    scan = {
        "assets":       assets,
        "assets_data":  data["assets"],
        "threads":      [],
        "options":      get_options(data),
        "scan_id":      scan_id,
        "status":       "STARTED",
        "lock":         False,
        "started_at":   int(time() * 1000),
        "findings":     {}
    }

    ENGINE.scans.update({scan_id: scan})
    thread = Thread(target=_scan_urls, args=(scan_id,))
    thread.start()
    ENGINE.scans[scan_id]["threads"].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan["scan_id"]
        }
    })

    LOG.warning(res)
    return jsonify(res)


def _scan_urls(scan_id):
    # Is it locked ?
    if ENGINE.scans[scan_id]["lock"]:
        LOG.warning("locked")
        return True

    ENGINE.scans[scan_id]["lock"] = True
    LOG.warning("lock on")

    assets = list()
    for asset in ENGINE.scans[scan_id]["assets"]:
        assets.append(asset)

    for i, asset in enumerate(assets):
        if asset not in ENGINE.scans[scan_id]["findings"]:
            ENGINE.scans[scan_id]["findings"][asset] = {}
        try:
            asset_data = next((x for x in ENGINE.scans[scan_id]["assets_data"] if x["value"] == asset), None)
            urls = list()
            if asset.startswith("http://"):
                urls.append("http://"+asset)
            elif asset.startswith("https://"):
                urls.append("https://"+asset)
            else:
                # Check both
                urls.append("http://"+asset)
                urls.append("https://"+asset)

            LOG.warning("[%s/%s] Screenshoting %s...", i+1, len(assets), asset)
            result = eyewitness_cmd(urls, asset_data["id"], scan_id, ENGINE.scans[scan_id]['options'])
            LOG.warning("[%s/%s] Screenshot result: %s", i+1, len(assets), result)

            # Get differences with the last screenshot
            for url in result:
                last_screenshot_path, last_screenshot_url = get_last_screenshot(result[url]["path"], asset_data["id"], scan_id)
                diff = diff_screenshot(result[url]["path"], last_screenshot_path)
                LOG.warning("[%s/%s] Screenshot diff: %s percent", i+1, len(assets), diff)
                result[url].update({
                    "previous_diff": diff,
                    "last_screenshot_path": last_screenshot_path,
                    "last_screenshot_url": last_screenshot_url})

            # Get the difference between the current screenshots
            current_diff = None
            if len(result) == 2:
                current_diff = diff_screenshot(result[urls[0]]["path"], result[urls[1]]["path"])
            result["current_diff"] = current_diff

            ENGINE.scans[scan_id]["findings"][asset]["issues"] = result
        except Exception as err_msg:
            LOG.error("_scan_urls: API Connexion error for asset %s: %s", asset, err_msg)
            return False

    LOG.warning("lock off")
    ENGINE.scans[scan_id]["lock"] = False
    return True


def _parse_results(scan_id):
    while ENGINE.scans[scan_id]["lock"]:
        LOG.warning("report is not terminated yet, going to sleep")
        sleep(10)

    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    timestamp = datetime.now()

    for asset in ENGINE.scans[scan_id]["findings"]:
        cvss_max = float(0)
        if ENGINE.scans[scan_id]["findings"][asset]["issues"]:
            asset_issues = ENGINE.scans[scan_id]["findings"][asset]["issues"]
            screenshot_urls = list()
            report_urls = list()
            is_for_sale = False
            if not asset_issues:
                screenshot_urls = "No screenshots available"
            for url in asset_issues:
                if url == "current_diff":
                    continue
                screenshot_urls.append(asset_issues[url]["url"])
                report_urls.append(asset_issues[url]["report"])
                # Create an issue if the screenshot differs from last time
                previous_diff = asset_issues[url]["previous_diff"]
                is_for_sale = is_forsale(asset_issues[url]["report_sources_path"]) or is_for_sale
                if previous_diff is None:
                    nb_vulns[get_criticity(cvss_max)] += 1
                    issues.append({
                        "issue_id": len(issues)+1,
                        "severity": "medium", "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "http"},
                        "title": "[{}] Screenshot differs from last time".format(timestamp),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}, "links": [asset_issues[url]["url"], asset_issues[url]["last_screenshot_url"]]},
                        "type": "eyewitness_screenshot_diff",
                        "timestamp": timestamp,
                        "description": "Too much differences, Domain for sale: {}.".format(is_for_sale)
                    })
                elif previous_diff >= COMPARE_CEIL:
                    nb_vulns[get_criticity(cvss_max)] += 1
                    issues.append({
                        "issue_id": len(issues)+1,
                        "severity": "medium", "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "http"},
                        "title": "[{}] Screenshot differs from last time".format(timestamp),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}, "links": [asset_issues[url]["url"], asset_issues[url]["last_screenshot_url"]]},
                        "type": "eyewitness_screenshot_diff",
                        "timestamp": timestamp,
                        "description": "The difference is about {}%, Domain for sale: {}.".format(previous_diff, is_for_sale)
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
                "metadata": {"risk": {"cvss_base_score": cvss_max}, "links": report_urls},
                "type": "eyewitness_screenshot",
                "timestamp": timestamp,
                "description": "Screenshots: {}, Current Diff: {}, Domain for sale: {}".format(screenshot_urls, current_diff, is_for_sale)
            })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "eyewitness",
        "engine_version": ENGINE.scanner["version"]
    }

    return issues, summary


@app.route("/engines/eyewitness/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    """Return all findings."""
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in ENGINE.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        LOG.warning(res)
        return jsonify(res)

    # check if the scan is finished
    status()
    if ENGINE.scans[scan_id]["status"] != "FINISHED":
        res.update({"status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, ENGINE.scans[scan_id]["status"])})
        LOG.warning(res)
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": ENGINE.scans[scan_id]["assets"],
        "options": ENGINE.scans[scan_id]["options"],
        "status": ENGINE.scans[scan_id]["status"],
        "started_at": ENGINE.scans[scan_id]["started_at"],
        "finished_at": ENGINE.scans[scan_id]["finished_at"]
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
        os.makedirs(APP_BASE_DIR+"/results")
    _loadconfig()
    LOG.warning("Run engine")


if __name__ == "__main__":
    ENGINE.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
