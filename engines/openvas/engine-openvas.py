#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

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
from gvm.connections import TLSConnection
from gvm.protocols.latest import Gmp

# Own library
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
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
this.gmp = None


def is_uuid(uuid_string, version=4):
    """
    This functionuuid_string returns True is the uuid_string is a valid UUID.
    """
    try:
        uid = UUID(uuid_string, version=version)
        return uid.hex == uuid_string.replace("-", "")
    except ValueError:
        return False


def get_options(payload):
    """
    Extracts formatted options from the payload.
    """
    options = {"enable_create_target": True, "enable_create_task": True, "enable_start_task": True}
    user_opts = payload["options"]
    if "enable_create_target" in user_opts:
        options["enable_create_target"] = user_opts["enable_create_target"] == "True" or user_opts["enable_create_target"] == "True"
    if "enable_create_task" in user_opts:
        options["enable_create_task"] = user_opts["enable_create_task"] == "True" or user_opts["enable_create_task"] == "True"
    if "enable_start_task" in user_opts:
        options["enable_start_task"] = user_opts["enable_start_task"] == "True" or user_opts["enable_start_task"] == "True"
    return options


def get_target(target_name):
    """
    This function returns the target_id of a target. If not, it returns None.
    """
    targets_xml = this.gmp.get_targets()
    try:
        targets = ET.fromstring(targets_xml)
    except Exception:
        return None
    if not targets.attrib["status"] == "200":
        return None

    for target in targets.findall("target"):
        if target_name == target.find("hosts").text:
            target_id = target.get("id")
            if not is_uuid(target_id):
                return None
            return target_id

    return None


def get_credentials(name=None):
    """
    This function returns the credentials_id from conf.
    """
    result_xml = this.gmp.get_credentials()
    try:
        result = ET.fromstring(result_xml)
    except Exception:
        return None
    if not result.attrib["status"] == "200":
        return None

    creds_name = name
    if name is None:
        # Set the default value set in engine config
        creds_name = engine.scanner["options"]["default_credential_name"]["value"]

    for credential in result.findall("credential"):
        if credential.find("name").text == creds_name:
            credentials_id = credential.attrib["id"]
            if not is_uuid(credentials_id):
                return None
            return credentials_id
    return None


def get_scan_config(name=None):
    """
    This function returns the scan_config_id from conf.
    """
    configs_xml = this.gmp.get_configs()
    try:
        configs = ET.fromstring(configs_xml)
    except Exception:
        return None

    scan_config_name = name
    if name is None:
        # Set the default value set in engine config
        scan_config_name = engine.scanner["options"]["default_scan_config_name"]["value"]

    for config in configs.findall("config"):
        tmp_config_name = config.find("name").text
        if scan_config_name == tmp_config_name:
            scan_config_id = config.get("id")
            if not is_uuid(scan_config_id, version=1) and not is_uuid(scan_config_id):
                return None
            return scan_config_id
    return None


def create_target(
    target_name,
    ssh_credential_id=None, ssh_credential_port=None,
    smb_credential_id=None,
    esxi_credential_id=None,
    snmp_credential_id=None):
    """
    This function creates a target in OpenVAS and returns its target_id.
    """
    new_target_xml = this.gmp.create_target(
        target_name,
        hosts=target_name,
        ssh_credential_id=ssh_credential_id,
        ssh_credential_port=ssh_credential_port,
        smb_credential_id=smb_credential_id,
        esxi_credential_id=esxi_credential_id,
        snmp_credential_id=snmp_credential_id
        )
    try:
        new_target = ET.fromstring(new_target_xml)
    except Exception:
        return None
    if not new_target.get("status") == "201":
        return None
    target_id = new_target.get("id")
    if not is_uuid(target_id):
        return None
    return target_id


def get_task_by_target_name(target_name):
    """
    This function returns the task_id.
    """
    tasks_xml = this.gmp.get_tasks()
    target_id = get_target(target_name)
    if target_id is None:
        return None
    try:
        tasks = ET.fromstring(tasks_xml)
    except Exception:
        return None
    if not tasks.get("status") == "200":
        return None

    for task in tasks.findall("task"):
        if task.find('target').get("id") == target_id:
            task_id = task.get("id")
            if not is_uuid(task_id):
                return None
            return task_id

    return None


def get_scanners(name=None):
    """
    This function returns the list of scanners' ID.
    """
    scanners_xml = this.gmp.get_scanners()
    try:
        scanners = ET.fromstring(scanners_xml)
    except Exception:
        return None
    if not scanners.get("status") == "200":
        return None

    scanners_list = []

    for scanner in scanners.findall("scanner"):
        if name is not None:
            if name == scanner.find('name').text:
                return [scanner.get("id")]
        else:
            scanners_list.append(scanner.get("id"))
    return scanners_list


def create_task(target_name, target_id, scan_config_id=None, scanner_id=None):
    """
    This function creates a task_id in OpenVAS and returns its task_id.
    """
    if scan_config_id is None:
        scan_config_id = get_scan_config()  # Set the default value
    if scanner_id is None:
        scanner_id = get_scanners()[1]  # Set the default value

    new_task_xml = this.gmp.create_task(
        name=target_name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id
    )
    try:
        new_task = ET.fromstring(new_task_xml)
    except Exception:
        return None
    if not new_task.get("status") == "201":
        return None

    task_id = new_task.get("id")
    if not is_uuid(task_id):
        return None
    return task_id


def start_task(task_id):
    """
    This function starts a task and returns a report_id.
    """
    start_scan_results_xml = this.gmp.start_task(task_id)

    try:
        start_scan_results = ET.fromstring(start_scan_results_xml)
    except Exception:
        return None
    if not start_scan_results.get("status") == "202":
        return None
    report_id = start_scan_results.find("report_id").text
    if report_id == "0" or not is_uuid(report_id):
        return None
    return report_id


def get_last_report(task_id):
    """
    This function returns the last report_id of a task_id
    """
    task_xml = this.gmp.get_task(task_id)
    try:
        task = ET.fromstring(task_xml)
    except Exception:
        return None
    if not task.get("status") == "200":
        return None

    last_report = task.find("task").find("last_report").find("report")
    if not is_uuid(last_report.get("id")):
        return None
    return last_report.get("id")


def get_report_status(report_id):
    """
    This function get the status of a report_id.
    """
    report_status_xml = this.gmp.get_report(report_id)
    try:
        report_status = ET.fromstring(report_status_xml)
    except Exception:
        return None
    if not report_status.get("status") == "200":
        return None

    return report_status.find("report").find("report").find("scan_run_status").text


def get_multiple_report_status(assets):
    """
    This function get the status of a set of assets {'task_id': xx, 'report_id': xx}
    """
    assets_status = dict()
    result_xml = this.gmp.get_tasks()
    try:
        result = ET.fromstring(result_xml)
    except Exception:
        return None
    if not result.attrib["status"] == "200":
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
            res.update({
                "status": "error",
                "reason": "scan_urls did not worked ! ({})".format(e)})
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
    if not exists(conf_file):
        print("Error: config file '{}' not found".format(conf_file))

    json_data = open(conf_file)
    engine.scanner = load(json_data)

    try:
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"]
        )
        this.gmp = Gmp(connection)
        this.gmp.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"])
    except Exception:
        engine.scanner["status"] = "ERROR"
        print("Error: authentication failure Openvas instance")
        return False

    engine.scanner["status"] = "READY"
    engine.scanner["credentials"] = ()
    engine.scanner["scan_config"] = get_scan_config()

    # print(create_target("toto1.patrowl.io"))
    # print(get_task_by_target_name("patrowl.io"))
    # print(get_scanners())
    # print(get_scanners("OpenVAS Default"))
    # print(get_scan_config())
    # print(get_scan_config(name="Discovery"))
    # print(get_credentials())
    # print(get_credentials(name="coucou"))
    # print(create_task(target_name="patrowl.io", target_id="0f388a01-dcef-483c-90ea-4fbd3788ee0d"))
    # print(start_task(create_task(target_name="www.patrowl.io", target_id="0f388a01-dcef-483c-90ea-4fbd3788ee0d")))
    # print(get_last_report("dd63bb59-345b-41d0-a80f-47372eebbeab"))
    # print(get_report_status("38db1f52-40d1-451d-ae9f-955c1d8ac1bd"))


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

    assets_failure = list()
    scan["assets"] = dict()

    for asset in assets:
        # print("== {} ==".format(asset))
        target_id = get_target(asset)
        if target_id is None and options["enable_create_target"]:
            # print("Create target {}".format(asset))
            target_id = create_target(asset)  # Todo: add credentials if needed
        if target_id is None:
            # if options["enable_create_target"]:
            #     print("Fail to create target {}".format(asset))
            # else:
            #     print("Target creation disabled")
            assets_failure.append(asset)
        else:
            task_id = get_task_by_target_name(asset)
            if task_id is None and options["enable_create_task"]:
                # print("Create task {}".format(asset))
                task_id = create_task(asset, target_id)
            if task_id is None:
                # if options["enable_create_task"]:
                #     print("Fail to create task {}".format(asset))
                # else:
                #     print("Task creation disabled")
                assets_failure.append(asset)
            else:
                if options["enable_start_task"]:
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
                    scan["assets"].update({
                        asset: {
                            "task_id": task_id,
                            "report_id": report_id,
                            "status": "accepted"
                        }
                    })

    # if scan["assets"] == dict():
    #     res.update({
    #         "status": "refused",
    #         "details": {
    #             "reason": "scan '{}' is probably already launched".format(data["scan_id"]),
    #         }
    #     })
    #     return jsonify(res)

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
        except Exception:
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
        result = this.gmp.get_report(report_id)
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
        except Exception:
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
            description = description + "For more detail go to 'https://{gmp_host}/omp?cmd=get_report&report_id={report_id}'".format(
                gmp_host=engine.scanner["options"]["gmp_host"]["value"],
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
        res.update({
            "status": "error",
            "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]["status"])
        })
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
    with open(APP_BASE_DIR+"/results/openvas_"+scan_id+".json", "w") as rf:
        dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, rf, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"
    })
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not exists(APP_BASE_DIR+"/results"):
        makedirs(APP_BASE_DIR+"/results")
    _loadconfig()


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
