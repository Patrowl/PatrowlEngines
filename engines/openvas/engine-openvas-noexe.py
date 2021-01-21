#!/usr/bin/python
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

import os
import sys
import json
import time
import threading
from urllib.parse import urlparse
# import random
# import string
from datetime import date, datetime
from uuid import UUID
from flask import Flask, request, jsonify
# from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions
import xml.etree.ElementTree as ET
from dns.resolver import query
# from dns.reversename import from_address
from openvas_lib import VulnscanManager, VulnscanException
from threading import Semaphore
from functools import partial

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = 5
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_OV_PROFILE = "Full and fast"
DEFAULT_OV_PORTLIST = "patrowl-all_tcp"
VERSION = "1.4.18"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)

this = sys.modules[__name__]
this.openvas_cli = None
this.openvas_portlists = {}


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        # if the obj is uuid, we simply return the value of uuid
        return obj.hex
    raise TypeError("Type %s not serializable" % type(obj))


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

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
    elif engine.scans[scan_id]["status"] == "STARTED":
        res.update({"status": "STARTED"})
    elif engine.scans[scan_id]["status"] == "SCANNING":
        ov_scan_status = "unknown"
        if engine.scans[scan_id]["ov_scan_id"] != "":
            ov_scan_status = this.openvas_cli.get_scan_status(engine.scans[scan_id]["ov_scan_id"])
        # print(ov_scan_status)
        if ov_scan_status not in ["Requested", "Running", "Done"]:
            res.update({"status": "ERROR"})
        else:
            res.update({"status": "SCANNING"})
    elif engine.scans[scan_id]["status"] == "FINISHED":
        res.update({"status": "FINISHED"})

    return jsonify(res)


@app.route('/engines/openvas/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/openvas/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "status", "status": "success"}
    """Stop scan identified by id."""
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})

    this.openvas_cli.stop_audit(scan_id)
    if engine.scans[scan_id]['status'] not in ["FINISHED", "ERROR"]:
        engine.scans[scan_id]['status'] = "STOPPED"

    return res


@app.route('/engines/openvas/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+'/openvas.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
        engine.scanner['status'] = "INIT"

        # Check omp connectivity
        if set(["omp_host", "omp_port", "omp_username", "omp_password"]).issubset(engine.scanner['options'].keys()):
            try:
                this.openvas_cli = VulnscanManager(
                    str(engine.scanner['options']['omp_host']['value']),
                    str(engine.scanner['options']['omp_username']['value']),
                    str(engine.scanner['options']['omp_password']['value']),
                    int(engine.scanner['options']['omp_port']['value']))
            except VulnscanException as e:
                print("Error: {}".format(e))
        else:
            print("Error: missing required options in config file".format(conf_file))
            engine.scanner['status'] = "ERROR"
            return {"status": "error", "reason": "missing required options"}

        for pl_name, pl_data in this.openvas_cli.get_port_lists().items():
            this.openvas_portlists.update({pl_name: pl_data['id']})

        # Create custom port lists
        if "patrowl-all_tcp" not in this.openvas_portlists.keys():
            new_pl_id = this.openvas_cli.create_port_list(
                name="patrowl-all_tcp",
                port_range="T:1-65535"
            )
            this.openvas_portlists.update({"patrowl-all_tcp": new_pl_id})

        if "patrowl-quick_tcp" not in this.openvas_portlists.keys():
            new_pl_id = this.openvas_cli.create_port_list(
                name="patrowl-quick_tcp",
                port_range="T:21-80,T:443,U:53"
            )
            this.openvas_portlists.update({"patrowl-quick_tcp": new_pl_id})

        if "patrowl-tcp_80" not in this.openvas_portlists.keys():
            new_pl_id = this.openvas_cli.create_port_list(
                name="patrowl-tcp_80",
                port_range="T:80"
            )
            this.openvas_portlists.update({"patrowl-tcp_80": new_pl_id})

        if "patrowl-tcp_443" not in this.openvas_portlists.keys():
            new_pl_id = this.openvas_cli.create_port_list(
                name="patrowl-tcp_443",
                port_range="T:443"
            )
            this.openvas_portlists.update({"patrowl-tcp_443": new_pl_id})

        if "patrowl-tcp_22" not in this.openvas_portlists.keys():
            new_pl_id = this.openvas_cli.create_port_list(
                name="patrowl-tcp_22",
                port_range="T:22"
            )
            this.openvas_portlists.update({"patrowl-tcp_22": new_pl_id})

        engine.scanner['status'] = "READY"
    else:
        print("Error: config file '{}' not found".format(conf_file))
        engine.scanner['status'] = "ERROR"
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
            parsed_uri = urlparse(asset["value"])
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

    # Checking default options
    ov_profile = DEFAULT_OV_PROFILE  # "Full and fast"
    ov_profiles = this.openvas_cli.get_profiles
    if "profile" in data['options'].keys():
        ov_p = str(data['options']['profile'])
        if ov_p in ov_profiles.keys():
            ov_profile = ov_p
    ov_port_list = DEFAULT_OV_PORTLIST  # "patrowl-all_tcp"
    ov_port_lists = this.openvas_cli.get_port_lists(abs)
    if "port_list" in data['options'].keys():
        ov_pl = str(data['options']['port_list'])
        if ov_pl in ov_port_lists.keys():
            ov_port_list = ov_pl

    scan = {
        'assets':       assets,
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'ov_scan_id':   "",
        'ov_target_id': "",
        'ov_profile':   ov_profile,
        'ov_port_list': ov_port_list,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'issues':       [],
        'summary':      {}
    }

    engine.scans.update({scan_id: scan})
    thread = threading.Thread(target=_scan, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]['threads'].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan(scan_id):
    assets = []
    for asset in engine.scans[scan_id]['assets']:
        assets.append(asset)

    ov_profile = engine.scans[scan_id]["ov_profile"]
    ov_port_list = engine.scans[scan_id]["ov_port_list"]

    # Start scan
    Sem = Semaphore(0)
    ov_scan_id, ov_target_id = this.openvas_cli.launch_scan(
        target=assets,
        profile=ov_profile,
        port_list=ov_port_list,
        callback_end=partial(lambda x: x.release(), Sem)
    )
    engine.scans[scan_id].update({
        'ov_scan_id':   ov_scan_id,
        'ov_target_id': ov_target_id,
        'scan_status':  "SCANNING",
        'status':  "SCANNING"
    })
    Sem.acquire()
    # Finished scan

    ov_report_id = this.openvas_cli.get_report_id(ov_scan_id)
    ov_results_xml = this.openvas_cli.get_report_xml(ov_report_id)
    report_filename = "{}/results/{}.xml".format(APP_BASE_DIR, scan_id)
    with open(report_filename, 'w') as report_file:
        print(ET.tostring(ov_results_xml))
        report_file.write(ET.tostring(ov_results_xml).decode())

    issues, summary = _parse_results(scan_id)

    engine.scans[scan_id]["issues"] = issues
    engine.scans[scan_id]["summary"] = summary
    engine.scans[scan_id]["finished_at"] = int(time.time() * 1000)
    engine.scans[scan_id]["status"] = "FINISHED"

    return True


def _parse_results(scan_id):
    issues = []
    issue_id = 1

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    report_filename = "{}/results/{}.xml".format(APP_BASE_DIR, scan_id)

    if not os.path.isfile(report_filename):
        return False

    try:
        tree = ET.parse(report_filename)
    except Exception:
        # No Element found in XML file
        return False

    report = tree.getroot().find("report").find("report")

    # Map IP addresses to domains/fqdn/
    all_assets = {}
    for host in report.findall("host"):
        host_ip = host.find("ip").text
        all_assets.update({host_ip: [host_ip]})
        for detail in host.findall("detail"):
            if detail.find("name").text == "hostname":
                host_name = detail.find("value").text
                all_assets[host_ip].append(host_name)

    for result in report.find("results").findall("result"):
        issue_meta = {}
        issue_name = result.find("name").text
        issue_desc = result.find("description").text
        host_ip = result.find("host").text
        assets = all_assets[host_ip]
        host_port = result.find("port").text

        # Severity
        threat = result.find("threat").text
        severity = "info"
        if threat == "High":
            severity = "high"
        elif threat == "Medium":
            severity = "medium"
        elif threat == "Low":
            severity = "low"

        issue_cvss = float(result.find("severity").text)

        if result.find("nvt").find("cve") is not None and result.find("nvt").find("cve").text != "NOCVE":
            cvelist = str(result.find("nvt").find("cve").text)
            issue_meta.update({"CVE": cvelist.split(", ")})
        if result.find("nvt").find("bid") is not None and result.find("nvt").find("bid").text != "NOBID":
            bid_list = str(result.find("nvt").find("bid").text)
            issue_meta.update({"BID": bid_list.split(", ")})
        if result.find("nvt").find("xref") is not None and result.find("nvt").find("xref").text != "NOXREF":
            xref_list = str(result.find("nvt").find("xref").text)
            issue_meta.update({"XREF": xref_list.split(", ")})

        issue = PatrowlEngineFinding(
            issue_id=issue_id,
            type="openvas_scan",
            title="{} ({})".format(issue_name, host_port),
            description=issue_desc,
            solution="n/a",
            severity=severity,
            confidence="firm",
            raw=ET.tostring(result, encoding='utf-8', method='xml'),
            target_addrs=assets,
            meta_tags=["openvas"],
            meta_risk={"cvss_base_score": issue_cvss},
            meta_vuln_refs=issue_meta
        )
        issues.append(issue._PatrowlEngineFinding__to_dict())

        nb_vulns[severity] += 1
        issue_id += 1


    # report_id = engine.scans[scan_id]["report_id"]

    # for asset in engine.scans[scan_id]["findings"]:
    #     if engine.scans[scan_id]["findings"][asset]["issues"]:
    #         description = ''
    #         cvss_max = float(0)
    #         for eng in engine.scans[scan_id]["findings"][asset]["issues"]:
    #             if float(eng[0]) > 0:
    #                 cvss_max = max(float(eng[0]), cvss_max)
    #                 description = description + "[%s] CVSS: %s - Associated CVE: %s" % (eng[2], eng[0], eng[1]) + "\n"
    #         description = description + "For more detail go to 'https://%s/omp?cmd=get_report&report_id=%s'" % (engine.scanner["options"]["omp_host"]["value"], report_id)
    #
    #         criticity = "high"
    #         if cvss_max == 0:
    #             criticity = "info"
    #         elif cvss_max < 4.0:
    #             criticity = "low"
    #         elif cvss_max < 7.0:
    #             criticity = "medium"
    #
    #         nb_vulns[criticity] += 1
    #
    #         issues.append({
    #             "issue_id": len(issues)+1,
    #             "severity": criticity, "confidence": "certain",
    #             "target": {"addr": [asset], "protocol": "http"},
    #             "title": "'{}' identified in openvas".format(asset),
    #             "solution": "n/a",
    #             "metadata": {},
    #             "type": "openvas_report",
    #             "timestamp": timestamp,
    #             "description": description,
    #         })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": 0,
        "engine_name": "openvas",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route('/engines/openvas/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # Check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # Check if the scan is finished
    status()
    if engine.scans[scan_id]['status'] != "FINISHED":
        res.update({"status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]['status'])})
        return jsonify(res)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]['assets'],
        "options": engine.scans[scan_id]['options'],
        "status": engine.scans[scan_id]['status'],
        "started_at": engine.scans[scan_id]['started_at'],
        "finished_at": engine.scans[scan_id]['finished_at']
    }

    summary = engine.scans[scan_id]['summary']
    issues = engine.scans[scan_id]['issues']

    # Store the findings in a file
    with open(APP_BASE_DIR+"/results/openvas_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # Remove the scan from the active scan list
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
