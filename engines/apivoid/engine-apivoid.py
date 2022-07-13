#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""APIVoid PatrOwl engine application."""

import os
import sys
import json
import time
import requests
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor
from ratelimit import limits, sleep_and_retry


from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5022
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 25))
APP_ENGINE_NAME = "apivoid"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
VERSION = "1.4.19"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)

this = sys.modules[__name__]
this.keys = []
this.pool = ThreadPoolExecutor(5)


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


@app.route('/engines/apivoid/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/apivoid/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/apivoid/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/apivoid/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/apivoid/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/apivoid/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/apivoid/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/apivoid/status')
def status():
    res = {"page": "status"}

    if len(engine.scans) == APP_MAXSCANS * 2:
        engine.scanner['status'] = "BUSY"
    else:
        engine.scanner['status'] = "READY"

    scans = []
    for scan_id in engine.scans.keys():
        status_scan(scan_id)
        scans.append({scan_id: {
            "status": engine.scans[scan_id]['status'],
            "started_at": engine.scans[scan_id]['started_at'],
            "assets": engine.scans[scan_id]['assets']
        }})

    res.update({
        "nb_scans": len(engine.scans),
        "status": engine.scanner['status'],
        "scanner": engine.scanner,
        "scans": scans})

    # print("thread-count:", threading.active_count())
    # for thread in threading.enumerate():
    #     print("{}:{}".format(thread.name, thread.native_id))
    return jsonify(res)


@app.route('/engines/apivoid/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    # return engine.getstatus_scan(scan_id)
    if scan_id not in engine.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)
        })

    all_threads_finished = True

    if 'futures' in engine.scans[scan_id]:
        for f in engine.scans[scan_id]['futures']:
            if not f.done():
                engine.scans[scan_id]['status'] = "SCANNING"
                all_threads_finished = False
                break
            else:
                engine.scans[scan_id]['futures'].remove(f)

    try:
        if all_threads_finished and len(engine.scans[scan_id]['threads']) == 0 and len(engine.scans[scan_id]['futures']) == 0:
            engine.scans[scan_id]['status'] = "FINISHED"
            engine.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    except Exception:
        pass

    return jsonify({"status": engine.scans[scan_id]['status']})


@app.route('/engines/apivoid/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/apivoid/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/apivoid/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR + '/apivoid.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)

        try:
            this.keys = os.environ.get('APIVOID_APIKEY', engine.scanner['apikeys'][0])
            engine.scanner['status'] = "READY"
        except Exception:
            this.keys = ""
            engine.scanner['status'] = "ERROR"
            app.logger.error("Error: No API KEY available")
            return {"status": "error", "reason": "No API KEY available"}

    else:
        app.logger.error("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}


@app.route('/engines/apivoid/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route('/engines/apivoid/startscan', methods=['POST'])
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
                "reason": "bad scanner status {}".format(engine.scanner['status'])
            }})
        return jsonify(res)

    data = json.loads(request.data)
    if 'assets' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "no asset specified"
            }})
        return jsonify(res)

    if 'scan_id' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan_id missing"
            }})
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update({
                "status": "error",
                "reason": "asset value missing"
            })
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update({
                "status": "error",
                "reason": "asset '{}' datatype '{}' not supported".format(asset["value"],asset["datatype"])
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

    scan = {
        'assets': assets,
        'threads': [],
        'futures': [],
        'options': data['options'],
        'scan_id': scan_id,
        'status': "STARTED",
        'started_at': int(time.time() * 1000),
        'findings': {}
    }

    engine.scans.update({scan_id: scan})
    # th = threading.Thread(target=_scan_ip_reputation, args=(scan_id,))
    # th.start()
    # engine.scans[scan_id]['threads'].append(th)

    if 'ip_reputation' in scan['options'].keys() and data['options']['ip_reputation']:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = this.pool.submit(_scan_ip_reputation, scan_id, asset["value"])
                engine.scans[scan_id]['futures'].append(th)

    if 'domain_reputation' in scan['options'].keys() and data['options']['domain_reputation']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = this.pool.submit(_scan_domain_reputation, scan_id, asset["value"])
                engine.scans[scan_id]['futures'].append(th)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan_ip_reputation(scan_id, asset):
    apikey = this.keys
    if asset not in engine.scans[scan_id]["findings"]:
        engine.scans[scan_id]["findings"][asset] = {}
    try:
        engine.scans[scan_id]["findings"][asset]['ip_reputation'] = get_report_ip_reputation(scan_id, asset, apikey)
    except Exception as ex:
        app.logger.error("_scan_ip_reputation failed {}".format(re.sub(r'/' + apikey + '/', r'/***/', ex.__str__())))
        return False

    return True


def _scan_domain_reputation(scan_id, asset):
    apikey = this.keys
    if asset not in engine.scans[scan_id]["findings"]:
        engine.scans[scan_id]["findings"][asset] = {}
    try:
        engine.scans[scan_id]["findings"][asset]['domain_reputation'] = get_report_domain_reputation(scan_id, asset, apikey)
    except Exception as ex:
        app.logger.error("_scan_domain_reputation failed {}".format(re.sub(r'/' + apikey + '/', r'/***/', ex.__str__())))
        return False

    return True

#
# def get_filename(scan_id, extension):
#     output_dir = f"{APP_BASE_DIR}/results/"
#
#     return "{}apivoid_{}.{}".format(
#         output_dir,
#         scan_id,
#         extension)

#
# def get_findingsfile(scan_id):
#     return get_filename(scan_id, "json")


@sleep_and_retry
@limits(calls=2, period=1)
def check_limit():
    """Empty function just to check for calls to API."""
    return


def get_report_ip_reputation(scan_id, asset, apikey):
    """Get APIvoid ip reputation report."""
    check_limit()
    scan_url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={apikey}&ip={asset}"

    try:
        response = requests.get(scan_url)
        # print(response.content)
    except Exception as ex:
        app.logger.error("get_report_ip_reputation failed {}".format(re.sub(r'/' + apikey + '/', r'/***/', ex.__str__())))
        return []

    return response.content


def get_report_domain_reputation(scan_id, asset, apikey):
    """Get APIvoid domain report."""
    check_limit()
    scan_url = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={apikey}&host={asset}"

    try:
        response = requests.get(scan_url)
        # print(response.content)
    except Exception as ex:
        app.logger.error("get_report_domain_reputation failed {}".format(re.sub(r'/' + apikey + '/', r'/***/', ex.__str__())))
        return []

    return response.content


def _parse_results(scan_id):
    status = {"status": "success"}
    issues = []
    summary = {}
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    ts = int(time.time() * 1000)

    for asset in engine.scans[scan_id]["findings"]:
        if 'ip_reputation' in engine.scans[scan_id]["findings"][asset].keys():
            res = json.loads(engine.scans[scan_id]["findings"][asset]['ip_reputation'])
            if 'data' in res:
                nb_vulns['info'] += 1
                issues.append({
                    "issue_id": len(issues) + 1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                    },
                    "title": "IP Reputation Check",
                    "description": f"IP Reputation Check for '{asset}'\n\nSee raw_data",
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["ip", "reputation"]
                    },
                    "type": "ip_reputation",
                    "raw": res['data'],
                    "timestamp": ts
                })
        if 'domain_reputation' in engine.scans[scan_id]["findings"][asset].keys():
            res = json.loads(engine.scans[scan_id]["findings"][asset]['domain_reputation'])
            if 'data' in res:
                nb_vulns['info'] += 1
                issues.append({
                    "issue_id": len(issues) + 1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                    },
                    "title": "IP Reputation Check",
                    "description": f"Domain Reputation Check for '{asset}'\n\nSee raw_data",
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domain", "reputation"]
                    },
                    "type": "ip_reputation",
                    "raw": res['data'],
                    "timestamp": ts
                })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "apivoid",
        "engine_version": engine.scanner["version"]
    }

    return status, issues, summary


@app.route('/engines/apivoid/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    # check if the scan is finished
    status_scan(scan_id)
    if engine.scans[scan_id]['status'] != "FINISHED":
        res.update({"status": "error",
                    "reason": f"scan_id '{scan_id}' not finished (status={engine.scans[scan_id]['status']})"})
        return jsonify(res)

    status, issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]['assets'],
        "options": engine.scans[scan_id]['options'],
        "started_at": engine.scans[scan_id]['started_at'],
        "finished_at": engine.scans[scan_id]['finished_at']
    }

    scan.update(status)
    # # Store the findings in a file
    # with open(get_findingsfile(scan_id), 'w') as report_file:
    #     json.dump({
    #         "scan": scan,
    #         "summary": summary,
    #         "issues": issues
    #     }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({"scan": scan, "summary": summary, "issues": issues})
    res.update(status)
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR + "/results"):
        os.makedirs(APP_BASE_DIR + "/results")
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
