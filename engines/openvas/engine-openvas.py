#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

from __future__ import absolute_import

from os import makedirs
from os.path import dirname, exists, isfile, realpath
from sys import modules
from json import dump, load, loads
from re import search as re_search
from subprocess import check_output
from threading import Thread
from time import time, sleep
from urllib.parse import urlparse
from uuid import UUID
import xml.etree.ElementTree as ET

# Third party library imports
from flask import Flask, request, jsonify
from dns.resolver import query

# Own library
## Temporary
import sys
sys.path.append("../utils")
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = 5
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = dirname(realpath(__file__))

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

this = modules[__name__]
this.keys = []

def is_uuid(uuid_string, version=4):
    """
    This functionuuid_string returns True is the uuid_string is a valid UUID
    """
    try:
        uid = UUID(uuid_string, version=version)
        return uid.hex == uuid_string.replace("-", "")
    except ValueError:
        return False

def get_options(payload):
    """
    Extracts formatted options from the payload
    """
    options = {"enable_create_target": True, "enable_create_task": True, "enable_start_task": True}
    user_opts = payload["options"]
    if "enable_create_target" in user_opts:
        options["enable_create_target"] = user_opts["enable_create_target"] == "True" or user_opts["enable_create_target"] == "true"
    if "enable_create_task" in user_opts:
        options["enable_create_task"] = user_opts["enable_create_task"] == "True" or user_opts["enable_create_task"] == "true"
    if "enable_start_task" in user_opts:
        options["enable_start_task"] = user_opts["enable_start_task"] == "True" or user_opts["enable_start_task"] == "true"
    return options

def omp_cmd(command):
    """ This function returns the output of an 'omp' command """
    omp_cmd_base = ["omp",
                    "-h", engine.scanner["options"]["omp_host"]["value"],
                    "-p", engine.scanner["options"]["omp_port"]["value"],
                    "-u", engine.scanner["options"]["omp_username"]["value"],
                    "-w", engine.scanner["options"]["omp_password"]["value"]]
    try:
        result = check_output(omp_cmd_base + command).decode("utf-8")
    except Exception as e:
        result = ""
    return result

def get_target(target_name):
    """
    This function returns the target_id of a target. If not, it returns None
    """
    result = omp_cmd(["--get-targets"]).split("\n")
    for target in result:
        if target_name in target:
            target_id = target.split(" ")[0]
            if not is_uuid(target_id):
                return None
            return target_id
    return None

def get_credentials():
    """
    This function returns the credentials_id from conf
    """
    result_xml = omp_cmd(["--xml", "<get_credentials/>"])
    try:
        result = ET.fromstring(result_xml)
    except:
        return None
    if not result.attrib["status"] == "200":
        return None
    for credential in result.findall("credential"):
        if credential.find("name").text == engine.scanner["options"]["credential_name"]["value"]:
            credentials_id = credential.attrib["id"]
            if not is_uuid(credentials_id):
                return None
            return credentials_id
    return None

def get_scan_config():
    """
    This function returns the scan_config_id from conf
    """
    result = omp_cmd(["--get-configs"]).split("\n")
    for config in result:
        if engine.scanner["options"]["scan_config_name"]["value"] in config:
            scan_config_id = config.split(" ")[0]
            if not is_uuid(scan_config_id, version=1):
                return None
            return scan_config_id
    return None

def create_target(target_name):
    """
    This function creates a target in OpenVAS and returns its target_id
    """
    result_xml = omp_cmd(["--xml",
                          "<create_target><name>{target_name}</name><hosts>{target_name}</hosts><ssh_credential id='{credentials_name}'><port>%{ssh_port}</port></ssh_credential></create_target>".format(
                              target_name=target_name,
                              credentials_name=engine.scanner["credentials"],
                              ssh_port=22)])
    try:
        result = ET.fromstring(result_xml)
    except:
        return None
    if not result.attrib["status"] == "201":
        return None
    target_id = result.attrib["id"]
    if not is_uuid(target_id):
        return None
    return target_id

def get_task(target_name):
    """
    This function returns the task_id
    """
    result = omp_cmd(["--get-tasks"]).split("\n")
    for target in result:
        if target_name in target:
            task_id = target.split(" ")[0]
            if not is_uuid(task_id):
                return None
            return task_id
    return None

def create_task(target_name, target_id):
    """
    This function creates a task_id in OpenVAS and returns its task_id
    """
    result = omp_cmd(["-C", "-c", engine.scanner["scan_config"], "--name", target_name, "--target", target_id]).split("\n")
    task_id = result[0]
    if not is_uuid(task_id):
        return None
    return task_id

def start_task(task_id):
    """
    This function starts a task and returns a report_id
    """
    result = omp_cmd(["-S", task_id]).split("\n")
    report_id = result[0]
    if not is_uuid(report_id):
        return None
    return report_id

def get_last_report(task_id):
    """
    This function returns the last report_id of a task_id
    """
    result = omp_cmd(["--get-tasks", task_id]).split("\n")
    try:
        report_id = result[-2].split("  ")[1]
    except IndexError:
        return None
    if not is_uuid(report_id):
        return None
    return report_id

def get_report_status(task_id, report_id):
    """
    This function get the status of a report_id
    """
    result = omp_cmd(["--get-tasks", task_id]).split("\n")
    for report in result:
        if report_id in report:
            return report.split("  ")[2]
    return None

def get_multiple_report_status(assets):
    """
    This function get the status of a set of assets {'task_id': xx, 'report_id': xx}
    """
    assets_status = dict()
    result_xml = omp_cmd(["--xml", "<get_tasks/>"])
    try:
        result = ET.fromstring(result_xml)
    except Exception as e:
        # print(e)
        return None
    if not result.attrib["status"] == "200":
        # print(result.attrib)
        return None
    for asset in assets:
        task_id = assets[asset]["task_id"]
        report_id = assets[asset]["report_id"]
        report = result.find("task/[@id='{task_id}']/*/report[@id='{report_id}']".format(
            task_id=task_id, report_id=report_id))
        if report is None:
            # print("Can't find task_id={task_id}, report_id={report_id}".format(
            #     task_id=task_id, report_id=report_id))
            assets_status.update({asset: {"status": "Failure"}})
        else:
            scan_end = report.find("scan_end").text
            if scan_end is None:
                assets_status.update({asset: {"status": "Running"}})
            else:
                assets_status.update({asset: {"status": "Done"}})
    return assets_status

def is_ip(string):
    """ This dummy function returns True is the string is probably an IP """
    return re_search("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", string) is not None

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


@app.route("/engines/openvas/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/openvas/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/openvas/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/openvas/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/openvas/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/openvas/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/openvas/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/openvas/status")
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route("/engines/openvas/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    report_status = "Done"

    assets = engine.scans[scan_id]["assets"]
    assets_status = get_multiple_report_status(assets)
    if assets_status is None:
        res.update({"status": "error", "reason": "Cannot find any report_status"})
        return jsonify(res)

    for asset in assets:
        if assets_status[asset]["status"] != "Done":
            report_status = assets_status[asset]["status"]

    engine.scans[scan_id]["scan_status"] = report_status

    if engine.scans[scan_id]["scan_status"] == "Done":
        res.update({"status": "FINISHED"})
        engine.scans[scan_id]["status"] = "FINISHED"
        # Get the last version of the report
        try:
            _scan_urls(scan_id)
        except Exception as e:
            res.update({"status": "error", "reason": "scan_urls did not worked ! ({})".format(e)})
            return jsonify(res)
    else:
        res.update({"status": "SCANNING"})
        for asset in assets:
            res.update({asset: assets_status[asset]["status"]})
        engine.scans[scan_id]["status"] = "SCANNING"

    return jsonify(res)


@app.route("/engines/openvas/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/openvas/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route("/engines/openvas/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+"/openvas.json"
    if exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = load(json_data)

        engine.scanner["status"] = "READY"
        engine.scanner["credentials"] = get_credentials()
        engine.scanner["scan_config"] = get_scan_config()

    else:
        # print("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}


@app.route("/engines/openvas/reloadconfig", methods=["GET"])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/openvas/startscan", methods=["POST"])
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
        "threads":      [],
        "options":      data["options"],
        "scan_id":      scan_id,
        "status":       "STARTED",
        "lock":         False,
        "started_at":   int(time() * 1000),
        "findings":     {}
    }

    options = get_options(data)

    new_task = False
    assets_failure = list()
    scan["assets"] = dict()

    for asset in assets:
        # print("== {} ==".format(asset))
        target_id = get_target(asset)
        if target_id is None and options["enable_create_target"]:
            # print("Create target {}".format(asset))
            target_id = create_target(asset)
        if target_id is None:
            # if options["enable_create_target"]:
            #     print("Fail to create target {}".format(asset))
            # else:
            #     print("Target creation disabled")
            assets_failure.append(asset)
        else:
            task_id = get_task(asset)
            if task_id is None and options["enable_create_task"]:
                # print("Create task {}".format(asset))
                task_id = create_task(asset, target_id)
                new_task = True
            if task_id is None:
                # if options["enable_create_task"]:
                #     print("Fail to create task {}".format(asset))
                # else:
                #     print("Task creation disabled")
                assets_failure.append(asset)
            else:
                if options["enable_start_task"] and (new_task or get_last_report(task_id) is None):
                    report_id = start_task(task_id)
                    if report_id is None:
                        # print("Get last report of {}".format(task_id))
                        report_id = get_last_report(task_id)
                else:
                    # print("Start task disabled, get last report of {}".format(task_id))
                    report_id = get_last_report(task_id)
                if report_id is None:
                    # if options["enable_start_task"]:
                    #     print("Fail to start task {}".format(task_id))
                    # else:
                    #     print("Task start disabled")
                    assets_failure.append(asset)
                else:
                    # print("OK for report_id {}".format(report_id))
                    scan["assets"].update({asset: {"task_id": task_id, "report_id": report_id, "status": "accepted"}})


    if scan["assets"] == dict():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' is probably already launched".format(data["scan_id"]),
            }
        })
        return jsonify(res)

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
        # print("locked")
        return True

    # Does the scan is terminated ?
    if "scan_status" in engine.scans[scan_id].keys():
        scan_status = engine.scans[scan_id]["scan_status"]
    else:
        return True
    if scan_status != "Done":
        return True

    engine.scans[scan_id]["lock"] = True
    # print("lock on")

    assets = []
    for asset in engine.scans[scan_id]["assets"]:
        assets.append(asset)

    for asset in assets:
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            engine.scans[scan_id]["findings"][asset]["issues"] = get_report(asset, scan_id)
        except Exception as e:
            # print("_scan_urls: API Connexion error (quota?)")
            # print(e)
            return False

    # print("lock off")
    engine.scans[scan_id]["lock"] = False
    return True


def get_report(asset, scan_id):
    """Get report."""
    report_id = engine.scans[scan_id]["assets"][asset]["report_id"]
    issues = []

    if not isfile("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset)):
        result = omp_cmd(["--get-report", report_id])
        result_file = open("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset), "w")
        result_file.write(result)
        result_file.close()

    try:
        tree = ET.parse("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset))
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
        # print("report is not terminated yet, going to sleep")
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
        if engine.scans[scan_id]["findings"][asset]["issues"]:
            report_id = engine.scans[scan_id]["assets"][asset]["report_id"]
            description = ""
            cvss_max = float(0)
            for eng in engine.scans[scan_id]["findings"][asset]["issues"]:
                if float(eng[0]) > 0:
                    cvss_max = max(float(eng[0]), cvss_max)
                    description = description + "[{threat}] CVSS: {severity} - Associated CVE : {cve}".format(
                        threat=eng[2],
                        severity=eng[0],
                        cve=eng[1]) + "\n"
            description = description + "For more detail go to 'https://{omp_host}/omp?cmd=get_report&report_id={report_id}'".format(
                omp_host=engine.scanner["options"]["omp_host"]["value"],
                report_id=report_id)

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
                "metadata": {"risk": {"cvss_base_score": cvss_max}},
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


@app.route("/engines/openvas/getfindings/<scan_id>", methods=["GET"])
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
    with open(APP_BASE_DIR+"/results/openvas_"+scan_id+".json", "w") as report_file:
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
    # print("Run engine")

if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
