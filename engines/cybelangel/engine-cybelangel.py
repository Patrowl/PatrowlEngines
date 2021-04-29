#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CybelAngel PatrOwl engine application

Copyright (C) 2021 Nicolas Mattiocco - @MaKyOtOx
Licensed under the AGPLv3 License
Written by Fabien Martinez (fabien.martinez@adevinta.com)
"""

import os
import sys
import json
import time
import logging
import threading
from pathlib import Path

from flask import Flask, request, jsonify
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

from cybelangel import CybelAngel

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 5))
APP_ENGINE_NAME = "cybelangel"
APP_BASE_DIR = Path(__file__).parent
VERSION = "1.0.0"

logging.basicConfig(level=(logging.DEBUG if APP_DEBUG else logging.INFO))
LOGGER = logging.getLogger('cybelangel')

engine = PatrowlEngine(
    app=app,
    base_dir=str(APP_BASE_DIR.absolute()),
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


@app.route('/engines/cybelangel/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/cybelangel/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/cybelangel/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/cybelangel/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/cybelangel/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/cybelangel/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/cybelangel/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/cybelangel/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/cybelangel/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    res.update({'status': engine.scans[scan_id]['status']})

    return jsonify(res)


@app.route('/engines/cybelangel/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/cybelangel/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/cybelangel/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR / 'cybelangel.json'
    try:
        json_data = conf_file.read_text()
    except FileNotFoundError:
        LOGGER.error(f'Unable to find config file "{conf_file.absolute()}"')
        return {"status": "error", "reason": "config file not found"}
    except Exception as e:
        LOGGER.error(f'Unable to read config file "{conf_file.absolute()}": {e}')
        return {"status": "error", "reason": "unable to read config file"}
    else:
        try:
            engine.scanner = json.loads(json_data)
        except Exception as e:
            LOGGER.error(f'Unable to convert config file to json: {e}')
            return {"status": "error", "reason": "unable to convert config file to json"}
        else:
            engine.scanner['status'] = 'READY'
        if 'options' not in engine.scanner:
            LOGGER.error("Unable to find options in config file")
            return {"status": "error", "reason": "you have to specify options in your config file"}
        for key, value in engine.scanner['options'].items():
            if not isinstance(value, dict) or not "type" in value.keys():
                LOGGER.error(f"Bad format for options! ({key})")
                return {"status": "error", "reason": f"bad format for options ({key})!"}
            if value['type'] == 'required' and len(value['value']) == 0:
                LOGGER.error(f'Required option empty / not found: {key}')
                return {"status": "error", "reason": f"you have to specify {key} in options"}


@app.route('/engines/cybelangel/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route('/engines/cybelangel/startscan', methods=['POST'])
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

    asset_groups = []
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

        asset_groups.append(asset["value"])

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
        'assets': asset_groups,
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'findings':     []
    }

    engine.scans.update({scan_id: scan})
    thread = threading.Thread(target=_scan_malicious_websites, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]['threads'].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan_malicious_websites(scan_id):
    cybelangel_manager = CybelAngel(
        engine.scanner['options']['api_client_id']['value'],
        engine.scanner['options']['api_client_secret']['value']
    )
    reports = cybelangel_manager.process()
    error = None
    if reports is False:
        LOGGER.error('Unable to get reports from cybelangel!')
        engine.scans[scan_id]['status'] = 'ERROR'
        return False
    engine.scans[scan_id]['findings'] = []
    if not error:
        for report in reports:
            LOGGER.info(f'Checking report threat {report["threat"]}')
            if not report['keywords'][0]['rule'].lower() in engine.scans[scan_id]['assets']:
                LOGGER.error(f'Unable to fin asset group for {report["threat"]}: {report["keywords"][0]["rule"]} found but no match')
                continue
            engine.scans[scan_id]['findings'].append({
                'domain': report['threat'],
                'asset_group': report['keywords'][0]['rule'].lower()
            })
            if not cybelangel_manager.resolve_report(report['id']):
                LOGGER.error(f'Unable to resolve report {report["threat"]}')
    engine.scans[scan_id]['status'] = 'FINISHED'
    engine.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    return True


def get_report(asset, scan_id):
    """Get report."""
    result = dict()
    result_file = APP_BASE_DIR / 'results' / f'cybelangel_{scan_id}.json'
    try:
        result = json.loads(result_file.read_text())
        result_file.close()
    except Exception:
        return {"status": "ERROR", "reason": "no issues found"}

    return result

def _parse_results(scan_id):
    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    timestamp = int(time.time() * 1000)

    for finding in engine.scans[scan_id]["findings"]:
        nb_vulns['medium'] +=  1
        issues.append({
                "issue_id": len(issues)+1,
                "severity": "medium",
                "confidence": "certain",
                "target": {"addr": [finding['domain']], "protocol": "http", "parent": finding['asset_group']},
                "title": f"[CybelAngel] New asset found on: {finding['domain']}",
                "solution": "n/a",
                "metadata": {"risk": {"criticity": "medium"}},
                "type": "cybelangel_report",
                "timestamp": timestamp,
                "description": f"Domain {finding['domain']} found as a malicious domain name by Cybel Angel",
        })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "cybelangel",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route('/engines/cybelangel/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
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
    report_file = APP_BASE_DIR / 'results' / f'cybelangel_{scan_id}.json'
    try:
        report_file.write_text(json.dumps({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, default=_json_serial))
    except Exception as e:
        LOGGER.error(f'Unable to write in {report_file.absolute()}: {e}')
        res.update({"status": "error", "reason": "unable to write in report file"})
    else:
        res.update({"scan": scan, "summary": summary, "issues": issues, "status": "success"})
    finally:
        # remove the scan from the active scan list
        clean_scan(scan_id)
        return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    result_path = APP_BASE_DIR / 'results'
    if not result_path.exists:
        result_path.mkdir(parents=True)
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
