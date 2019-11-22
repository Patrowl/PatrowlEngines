#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CertStream PatrOwl engine application."""

from json import dump, dumps, load, loads
from logging import getLogger
from os import makedirs
from os.path import dirname, exists, isfile, realpath
from sys import argv, modules, path
from threading import Thread
from time import time, sleep
from urllib.parse import urlparse

# Third party library imports
from flask import Flask, request, jsonify

LOG = getLogger("werkzeug")

# Own library
path.append("CertStreamMonitor")
try:
    from utils.confparser import ConfParser
    import gethost
except ModuleNotFoundError:
    LOG.warning("[WARNING] You have to 'git clone https://github.com/AssuranceMaladieSec/CertStreamMonitor.git'")

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5017
APP_MAXSCANS = 5
APP_ENGINE_NAME = "certstream"
APP_BASE_DIR = dirname(realpath(__file__))
CREATED_CERT_CVSS = 5
UP_DOMAIN_CVSS = 7
PARENT_ASSET_CREATE_FINDING_CVSS = 1
PARENT_ASSET_CREATE_FINDING_CEIL = 0

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

this = modules[__name__]
this.keys = []

def get_options(payload):
    """
    Extracts formatted options from the payload
    """

    options = {"since": 99999999999}
    user_opts = payload["options"]
    if isinstance(user_opts, str):
        user_opts = loads(user_opts)
    if "since" in user_opts:
        try:
            options["since"] = int(user_opts["since"])
        except Exception:
            options["since"] = 0
    return options

def get_criticity(score):
    """
    Returns the level of criicity
    """
    criticity = "high"
    if score == 0:
        criticity = "info"
    elif score < 4.0:
        criticity = "low"
    elif score < 7.0:
        criticity = "medium"
    return criticity

def in_whitelist(domain):
    """
    Returns True if the domain is in the whitelist
    """
    if not engine.scanner["options"]["Whitelist"]["present"]:
        return False
    whitelist = engine.scanner["options"]["Whitelist"]["list"]
    if domain in whitelist:
        return True
    for white in whitelist:
        if domain.endswith("."+white):
            return True
    return False

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


@app.route("/engines/certstream/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/certstream/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/certstream/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/certstream/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/certstream/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/certstream/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/certstream/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/certstream/status")
def status():
    """Get status on engine and all scans."""
    CertStreamMonitorFile = engine.scanner["options"]["CertStreamMonitorFile"]["value"]
    if not exists(CertStreamMonitorFile):
        LOG.error("Error: CertStreamMonitorFile not found : {}".format(CertStreamMonitorFile))
        return jsonify({"status": "error", "reason": "CertStreamMonitorFile not found : {}".format(CertStreamMonitorFile)})

    try:
        CONF = ConfParser(CertStreamMonitorFile)
        engine.scanner["options"]["DBFile"] = "CertStreamMonitor/" + CONF.DBFile
        engine.scanner["options"]["TABLEname"] = CONF.TABLEname
        engine.scanner["options"]["SearchKeywords"] = CONF.SearchKeywords
    except Exception:
        LOG.error("Error: Cannot read CertStreamMonitorFile : {}".format(CertStreamMonitorFile))
        return jsonify({"status": "error", "reason": "Cannot read CertStreamMonitorFile : {}".format(CertStreamMonitorFile)})

    if not exists(engine.scanner["options"]["DBFile"]):
        LOG.error("Error: sqlite file not found : {}".format(engine.scanner["options"]["DBFile"]))
        return jsonify({"status": "error", "reason": "sqlite file not found : {}".format(engine.scanner["options"]["DBFile"])})

    return engine.getstatus()


@app.route("/engines/certstream/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    res.update({"status": "FINISHED"})
    engine.scans[scan_id]["status"] = "FINISHED"
    # Get the last version of the report
    try:
        _scan_urls(scan_id)
    except Exception as e:
        res.update({"status": "error", "reason": "scan_urls did not worked ! ({})".format(e)})
        return jsonify(res)

    return jsonify(res)


@app.route("/engines/certstream/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/certstream/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route("/engines/certstream/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+"/certstream.json"
    if len(argv) > 1 and exists(APP_BASE_DIR+"/"+argv[1]):
        conf_file = APP_BASE_DIR + "/" + argv[1]
    if exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = load(json_data)
        engine.scanner["status"] = "READY"
    else:
        LOG.error("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}

    if "options" not in engine.scanner:
        LOG.error("Error: You have to specify options")
        return {"status": "error", "reason": "You have to specify options"}

    engine.scanner["options"]["Whitelist"]["present"] = "Whitelist" in engine.scanner["options"] and exists(engine.scanner["options"]["Whitelist"]["value"])

    with open(engine.scanner["options"]["Whitelist"]["value"], "r", encoding="UTF-8") as whitelist_file:
        whitelist = whitelist_file.read()
        engine.scanner["options"]["Whitelist"]["list"] = whitelist.split("\n")[:-1]

    if "CertStreamMonitorFile" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify CertStreamMonitorFile in options")
        return {"status": "error", "reason": "You have to specify CertStreamMonitorFile in options"}

    CertStreamMonitorFile = engine.scanner["options"]["CertStreamMonitorFile"]["value"]
    if not exists(CertStreamMonitorFile):
        LOG.error("Error: CertStreamMonitorFile not found : {}".format(CertStreamMonitorFile))
        return {"status": "error", "reason": "CertStreamMonitorFile not found : {}".format(CertStreamMonitorFile)}

    LOG.info("[OK] CertStreamMonitorFile")

    try:
        CONF = ConfParser(CertStreamMonitorFile)

        engine.scanner["options"]["DBFile"] = "CertStreamMonitor/" + CONF.DBFile
        engine.scanner["options"]["TABLEname"] = CONF.TABLEname
        engine.scanner["options"]["SearchKeywords"] = CONF.SearchKeywords
    except Exception:
        LOG.error("Error: Cannot read CertStreamMonitorFile : {}".format(CertStreamMonitorFile))
        return {"status": "error", "reason": "Cannot read CertStreamMonitorFile : {}".format(CertStreamMonitorFile)}

    if not exists(engine.scanner["options"]["DBFile"]):
        LOG.error("Error: sqlite file not found : {}".format(engine.scanner["options"]["DBFile"]))
        return {"status": "error", "reason": "sqlite file not found : {}".format(engine.scanner["options"]["DBFile"])}

@app.route("/engines/certstream/reloadconfig", methods=["GET"])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/certstream/startscan", methods=["POST"])
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
    # Default Value
    if not "options" in data:
        data["options"] = {"since": 3600}

    scan = {
        "assets":       assets,
        "threads":      [],
        "options":      data["options"],
        "scan_id":      scan_id,
        "status":       "STARTED",
        "lock":         False,
        "started_at":   int(time() * 1000),
        "findings":     {}
    }

    options = get_options(data)

    if options["since"] == 0:
        res.update({
            "status": "refused",
            "details": {
                "reason": "You need to specify a valid since options in seconds"}})
        return jsonify(res)

    engine.scanner["options"]["since"] = options["since"]

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

    # Does the scan is terminated ?
    if "status" in engine.scans[scan_id].keys():
        scan_status = engine.scans[scan_id]["status"]
    else:
        return True
    if scan_status != "FINISHED":
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
            engine.scans[scan_id]["findings"][asset]["issues"] = get_report(asset, scan_id)
        except Exception as e:
            LOG.error("_scan_urls: API Connexion error (quota?): {}".format(e))
            return False

    LOG.debug("lock off")
    engine.scans[scan_id]["lock"] = False
    return True


def get_report(asset, scan_id):
    """Get report."""
    result = dict()

    if not isfile("results/certstream_report_{scan_id}.txt".format(scan_id=scan_id)):
        gethost.SINCE = engine.scanner["options"]["since"]
        conn = gethost.create_connection(engine.scanner["options"]["DBFile"])
        result = gethost.parse_and_display_all_hostnames(engine.scanner["options"]["TABLEname"], conn)
        result_file = open("results/certstream_report_{scan_id}.txt".format(scan_id=scan_id), "w")
        result_file.write(dumps(result))
        result_file.close()

    try:
        result_file = open("results/certstream_report_{scan_id}.txt".format(scan_id=scan_id), "r")
        result = loads(result_file.read())
        result_file.close()
    except Exception:
        return {"status": "ERROR", "reason": "no issues found"}

    return result


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
        description = ""
        cvss_max = float(0)
        if engine.scans[scan_id]["findings"][asset]["issues"]:
            report = engine.scans[scan_id]["findings"][asset]["issues"]
            for domain in report:
                if in_whitelist(domain):
                    continue
                cvss_local = CREATED_CERT_CVSS
                description_local = "Domain: {} has been created\nIssuer: {}\nFingerprint {}\n".format(
                    domain,
                    report[domain]["issuer"],
                    report[domain]["fingerprint"])
                issues.append({
                    "issue_id": len(issues)+1,
                    "severity": get_criticity(cvss_local), "confidence": "certain",
                    "target": {"addr": [domain], "protocol": "http", "parent": asset},
                    "title": "Domain '{}' has been identified in certstream".format(domain),
                    "solution": "n/a",
                    "metadata": {"risk": {"cvss_base_score": cvss_local}},
                    "type": "certstream_report",
                    "timestamp": timestamp,
                    "description": description_local,
                })
                nb_vulns[get_criticity(cvss_local)] += 1

                if report[domain]["still_investing"] is not None:
                    cvss_local = UP_DOMAIN_CVSS
                    description_local += "Last time up: {}\n".format(report[domain]["still_investing"])
                    issues.append({
                        "issue_id": len(issues)+1,
                        "severity": get_criticity(cvss_local), "confidence": "certain",
                        "target": {"addr": [domain], "protocol": "http", "parent": asset},
                        "title": "Domain '{}' is reacheable".format(domain),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": cvss_local}},
                        "type": "certstream_report",
                        "timestamp": timestamp,
                        "description": description_local,
                    })
                    nb_vulns[get_criticity(cvss_local)] += 1

                cvss_max = max(cvss_local, cvss_max)
                description += description_local

        if cvss_max > PARENT_ASSET_CREATE_FINDING_CEIL:
            issues.append({
                "issue_id": len(issues)+1,
                "severity": get_criticity(PARENT_ASSET_CREATE_FINDING_CVSS), "confidence": "certain",
                "target": {"addr": [asset], "protocol": "http"},
                "title": "[{}] Some domain has been identified in certstream".format(timestamp),
                "solution": "n/a",
                "metadata": {"risk": {"cvss_base_score": PARENT_ASSET_CREATE_FINDING_CVSS}},
                "type": "certstream_report",
                "timestamp": timestamp,
                "description": description,
            })
            nb_vulns[get_criticity(PARENT_ASSET_CREATE_FINDING_CVSS)] += 1


    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "certstream",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route("/engines/certstream/getfindings/<scan_id>", methods=["GET"])
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
    with open(APP_BASE_DIR+"/results/certstream_"+scan_id+".json", "w") as rf:
        dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, rf, default=_json_serial)

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
