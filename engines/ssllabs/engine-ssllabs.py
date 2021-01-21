#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import sys
import requests
import json
import threading
import datetime
import time
import hashlib
import copy
import logging
from urllib.parse import urlparse
from flask import Flask, request, jsonify

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5004
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 25))
APP_ENGINE_NAME = "ssllabs"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_API_URL = "https://api.ssllabs.com/api/v3/"
VERSION = "1.4.18"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)

requests.packages.urllib3.disable_warnings()

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

'''
## Findings categories:
- supported_protocols
- accepted_ciphersuites
- ssl_common_issues (BROWN, FREAK, HEARTBLEED, CRIME, ...)
- ssl_configuration
- certificate_chain
- certificate_expiration
- certificate_revocation
- certificate_keysize
- certificate_cn
- certificate_name_match
- certificate_key_usages
- certificate_hash
- certificate_details

'''


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


@app.route('/engines/ssllabs/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/ssllabs/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/ssllabs/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/ssllabs/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/ssllabs/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/ssllabs/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/ssllabs/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/ssllabs/status')
def status():
    """Get status on engine and all scans."""
    res = {"page": "status"}
    if len(engine.scans) == APP_MAXSCANS:
        engine.scanner['status'] = "BUSY"
    else:
        engine.scanner['status'] = "READY"

    res.update({"status": engine.scanner['status']})

    # display info on the scanner
    res.update({"scanner": engine.scanner})
    scans = {}
    for scan in engine.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": engine.scans[scan]["status"]
        }})
    res.update({"scans": scans})
    return jsonify(res)

#
# @app.route('/engines/ssllabs/status/<scan_id>')
# def status_scan(scan_id):
#     """Get status on scan identified by id."""
#     return engine.getstatus_scan(scan_id)


@app.route('/engines/ssllabs/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/ssllabs/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/ssllabs/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+'/ssllabs.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
        if "api_url" not in engine.scanner.keys() or engine.scanner["api_url"] == "":
            engine.scanner["api_url"] = DEFAULT_API_URL

        try:
            r = requests.get(url=engine.scanner['api_url'] + 'info', verify=False)
            if r.status_code == 200:
                engine.scanner['status'] = 'READY'
            else:
                engine.scanner['status'] = 'ERROR'
        except Exception:
            engine.scanner['status'] = 'ERROR'

        return {"status": engine.scanner['status']}
    else:
        app.logger.debug("Error: config file '{}' not found".format(conf_file))
        return {
            "status": "error",
            "reason": "config file not found",
            "details": {
                "filename": conf_file
            }
        }


@app.route('/engines/ssllabs/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    res.update(_loadconfig())
    res.update({"config": engine.scanner})
    return jsonify(res)


def _is_scan_finished(scan_id):
    if scan_id not in engine.scans.keys():
        return False

    if engine.scans[scan_id]["status"] == "FINISHED":
        return True

    all_scans_done = False
    try:
        for host in engine.scans[scan_id]["assets"]:
            r = requests.get(url=host["url"], verify=False)
            if r.status_code == 200 and json.loads(r.text)["status"] in ["READY", "ERROR"]:
                all_scans_done = True

    except Exception:
        app.logger.debug("API connexion error")
        return False

    if all_scans_done is True:
        engine.scans[scan_id]["status"] = "FINISHED"
        engine.scans[scan_id]["finished_at"] = datetime.datetime.now()
        return True

    return False


@app.route('/engines/ssllabs/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    res = {"page": "scan_status"}

    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # @todo: check id the scan is finished or not
    _is_scan_finished(scan_id)

    # return the scan parameters and the status
    res.update({
        # "scan": engine.scans[scan_id],
        "status": engine.scans[scan_id]["status"]
    })

    return jsonify(res)


@app.route('/engines/ssllabs/startscan', methods=['POST'])
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
            }
        })
        return jsonify(res)

    scan = {}
    data = json.loads(request.data)

    # Check assets
    if 'assets' not in data.keys() or 'scan_id' not in data.keys():
        res.update({
            "status": "refused",
            "reason": "arg error, something is missing (ex: 'assets', 'scan_id')"
        })
        return jsonify(res)

    valid_assets = copy.deepcopy(data["assets"])
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            valid_assets.remove(asset)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            valid_assets.remove(asset)

        # url transform
        if asset["datatype"] == 'url':
            valid_assets.remove(asset)
            valid_assets.append({
                "id": asset["id"],
                "datatype": asset["datatype"],
                "criticity": asset["criticity"],
                "value": "{uri.netloc}".format(uri=urlparse(asset["value"]))
            })

    # Check scan_id
    scan["scan_id"] = str(data["scan_id"])
    if data["scan_id"] in engine.scans.keys():
        res.update({"status": "error", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    # Initialize the scan parameters
    if 'ports' not in data['options'].keys():
        scan["target_port"] = "443"
    else:
        scan["target_port"] = str(list(data['options']['ports'])[0])  # get the 1st in list

    scan["assets"] = []
    for asset in valid_assets:
        if asset["value"] not in [h["host"] for h in scan["assets"]]:
            target_host = asset["value"]
            target_url = "{}analyze?host={}&port={}&publish=off&ignoreMismatch=on&maxAge=2&fromCache=on".format(engine.scanner['api_url'], target_host, scan["target_port"])
            scan["assets"].append({"host": target_host, "url": target_url})

    scan["started_at"] = datetime.datetime.now()
    scan["status"] = "STARTED"
    scan["threads"] = []
    scan["findings"] = []

    engine.scans.update({scan["scan_id"]: scan})
    th = threading.Thread(target=_scan_urls, args=(scan["scan_id"],))
    th.start()
    engine.scans[scan["scan_id"]]['threads'].append(th)

    # Prepare data returned
    # res.update({"scan": scan})
    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def _scan_urls(scan_id):
    try:
        for host in engine.scans[scan_id]["assets"]:
            r = requests.get(url=host["url"], verify=False)
            if r.status_code == 200:
                engine.scans[scan_id]["status"] = "SCANNING"
            else:
                engine.scans[scan_id]["status"] = "ERROR"
                engine.scans[scan_id]["finished_at"] = datetime.datetime.now()
    except Exception:
        engine.scans[scan_id]["status"] = "ERROR"
        engine.scans[scan_id]["finished_at"] = datetime.datetime.now()
    return True


@app.route('/engines/ssllabs/getfindings/<scan_id>')
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    if not _is_scan_finished(scan_id):
        res.update({
            "status": "error",
            "reason": "scan '{}' not finished".format(scan_id)
        })
        return jsonify(res)

    scan = engine.scans[scan_id]
    port = scan['target_port']
    issues = []
    summary = {}
    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

    for host in scan["assets"]:
        try:
            r = requests.get(url=host["url"]+"&all=done", verify=False)
            if r.status_code != 200:
                res.update({
                    "status": "error",
                    "reason": "something wrong with the API invokation"
                })
                return jsonify(res)
        except Exception:
            res.update({
                "status": "error",
                "reason": "something wrong with the API invokation"
            })
            return jsonify(res)

        tmp_issues, tmp_summary = _parse_report(
            results=json.loads(r.text),
            asset_name=host["host"],
            asset_port=port
        )
        issues = issues + tmp_issues
        nb_vulns["info"] = nb_vulns["info"] + tmp_summary["nb_info"]
        nb_vulns["low"] = nb_vulns["low"] + tmp_summary["nb_low"]
        nb_vulns["medium"] = nb_vulns["medium"] + tmp_summary["nb_medium"]
        nb_vulns["high"] = nb_vulns["high"] + tmp_summary["nb_high"]
        nb_vulns["critical"] = nb_vulns["critical"] + tmp_summary["nb_critical"]

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "ssllabs",
        "engine_version": engine.scanner["version"]
    }

    # Store the findings in a file
    with open(APP_BASE_DIR+"/results/ssllabs_"+scan_id+".json", 'w') as report_file:
        json.dump({
            # "scan": engine.scans[scan_id],
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    res.update({
        "issues": issues,
        "summary": summary,
        "status": "success"})
    return jsonify(res)


def _parse_report(results, asset_name, asset_port):
    # Findings categories:
    # OK- ssllabs_grade
    # OK- supported_protocols
    # OK- accepted_ciphersuites
    # - ssl_common_flaws (BROWN, FREAK, HEARTBLEED, CRIME, ...) 'poodle', 'poodleTls', 'freak', 'drownVulnerable', 'vulnBeast', 'heartbleed'
    # - ssl_configuration
    # - certificate_chain
    # OK- certificate_expiration
    # - certificate_revocation
    # OK- certificate_keysize
    # OK- certificate_debianflaw
    # - certificate_cn
    # - certificate_name_match
    # - certificate_key_usages
    # - certificate_hash
    # - certificate_details
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
    if results["status"] == "ERROR":
        issues.append({
            "issue_id": 1,
            "severity": "info", "confidence": "certain",
            "target": {
                "addr": [asset_name],
                "port_id": asset_port,
                "port_type": 'tcp'
            },
            "title": results["statusMessage"],
            "description": results["statusMessage"],
            "solution": "Check the availability of the asset.",
            "type": "tls_access",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "availability"]
            },
            "raw": results["statusMessage"]
        })

        summary = {
            "nb_issues": 1,
            "nb_info": 1,
            "nb_low": 0,
            "nb_medium": 0,
            "nb_high": 0,
            "nb_critical": 0
        }

        return issues, summary

    endpoint = results["endpoints"][0]

    # Check results
    if "details" not in endpoint or len(endpoint['details']['protocols']) == 0:
        nb_vulns['info'] += 1
        issues.append({
            "issue_id": 1,
            "severity": "info", "confidence": "certain",
            "target": {
                "addr": [asset_name],
                "port_id": asset_port,
                "port_type": 'tcp'
            },
            "title": "Failed to communicate with the secure server.",
            "description": "Failed to communicate with the secure server.",
            "solution": "Check the availability of the asset.",
            "type": "tls_access",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "availability"]
            }
        })

        summary = {
            "nb_issues": 1,
            "nb_info": 1,
            "nb_low": 0,
            "nb_medium": 0,
            "nb_high": 0,
            "nb_critical": 0
        }
        return issues, summary

    # validity / expiration dates
    valid_from = datetime.datetime.fromtimestamp(endpoint["details"]["cert"]["notBefore"]/1000)
    valid_to = datetime.datetime.fromtimestamp(endpoint["details"]["cert"]["notAfter"]/1000)
    six_month_later = datetime.datetime.now() + datetime.timedelta(days=365/2)
    three_month_later = datetime.datetime.now() + datetime.timedelta(days=90)
    two_weeks_later = datetime.datetime.now() + datetime.timedelta(days=15)
    today_date = datetime.datetime.now()
    direct_link = "https://www.ssllabs.com/ssltest/analyze.html?d={}&hideResults=on&ignoreMismatch=on".format(asset_name)

    if valid_from > today_date:
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate not valid before '{}'".format(valid_from.isoformat()),
            "description": "The SSL/TLS certificate available at the address '{}' is not valid yet.\n\nScan date: {}\nNot valid before: {}".format(
                asset_name+":"+asset_port, today_date.isoformat(), valid_from.isoformat()
            ),
            "solution": "Review the certificate validity parameters",
            "type": "tls_certificate_validity",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "validity"]
            },
            "raw": endpoint["details"]["cert"]["notBefore"]
        })
    elif today_date > valid_to:
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate expired (not valid after '{}')".format(valid_to.isoformat()),
            "description": "The SSL/TLS certificate available at the address '{}' is expired.\n\nScan date: {}\nNot valid after: {}".format(
                asset_name+":"+asset_port, today_date.isoformat(), valid_to.isoformat()
            ),
            "solution": "Renew the certificate",
            "type": "tls_certificate_validity",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "validity", "expiration"],
                "links": [direct_link]
            },
            "raw": endpoint["details"]["cert"]["notAfter"]
        })
    elif valid_to < six_month_later:
        nb_vulns['low'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "low", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate valid until '{}' (less than 6 months)".format(valid_to.isoformat()),
            "description": "The SSL/TLS certificate available at the address '{}' is valid until '{}' (less than 6 months).\n\nScan date: {}\nNot valid after: {}".format(
                asset_name+":"+asset_port, valid_to.isoformat(), today_date.isoformat(), valid_to.isoformat()
            ),
            "solution": "Renew the certificate",
            "type": "tls_certificate_validity",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "validity", "expiration"],
                "links": [direct_link]
            },
            "raw": endpoint["details"]["cert"]["notAfter"]
        })
    elif valid_to < three_month_later:
        nb_vulns['medium'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "medium", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate valid until '{}' (less than 3 months)".format(valid_to.isoformat()),
            "description": "The SSL/TLS certificate available at the address '{}' is valid until '{}' (less than 3 months).\n\nScan date: {}\nNot valid after: {}".format(
                asset_name+":"+asset_port, valid_to.isoformat(), today_date.isoformat(), valid_to.isoformat()
            ),
            "solution": "Renew the certificate",
            "type": "tls_certificate_validity",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "validity", "expiration"],
                "links": [direct_link]
            },
            "raw": endpoint["details"]["cert"]["notAfter"]
        })
    elif valid_to < two_weeks_later:
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate valid until '{}' (less than 2 weeks)".format(valid_to.isoformat()),
            "description": "The SSL/TLS certificate available at the address '{}' is valid until '{}' (less than 2 weeks).\n\nScan date: {}\nNot valid after: {}".format(
                asset_name+":"+asset_port, valid_to.isoformat(), today_date.isoformat(), valid_to.isoformat()
            ),
            "solution": "Renew the certificate",
            "type": "tls_certificate_validity",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "validity", "expiration"],
                "links": [direct_link]
            },
            "raw": endpoint["details"]["cert"]["notAfter"]
        })

    # grade
    if endpoint["grade"] == "T":
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate not trusted (SSL-Labs Grade ='{}', and '{}' if ignored)".format(endpoint["grade"], endpoint["gradeTrustIgnored"]),
            "description": "The SSL/TLS certificate available at the address '{}' is not trusted.\nTrust issues (T): If we don’t trust a certificate (and there aren’t any other security issues), we assign it a T grade (for 'trust'). This grade is thus used when the server is otherwise well-configured. Just below the T grade, we note the grade the server would get if the trust issues were resolved".format(
                asset_name+":"+asset_port
            ),
            "solution": "View the detailled findings",
            "type": "tls_ssllabs_grade",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "grade", "trust"],
                "links": [direct_link, "https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide"]
            },
            "raw": endpoint["grade"]
        })
    elif endpoint["grade"] == "M":
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate name mismath (SSL-Labs Grade ='{}')".format(endpoint["grade"]),
            "description": "The SSL/TLS certificate at the address '{}' have name mismatch issues.\nName mismatch issues (M): In some cases, trust issues come from name mismatches and usually when a server doesn’t actually use encryption. Such sites now get an M grade (for 'mismatch').".format(
                asset_name+":"+asset_port
            ),
            "solution": "View the detailled findings",
            "type": "tls_ssllabs_grade",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "grade", "mismatch"],
                "links": [direct_link, "https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide"]
            },
            "raw": endpoint["grade"]
        })
    else:
        if endpoint["grade"] in ["A", "A+"]:
            sev = "info"
        elif endpoint["grade"] in ["A-", "B"]:
            sev = "low"
        elif endpoint["grade"] in ["C", "D"]:
            sev = "medium"
        else:
            sev = "high"

        nb_vulns[sev] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": sev, "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "SSL/TLS certificate security level: {} (SSL-Labs Grade)".format(endpoint["grade"]),
            "description": "Using the Qualys SSL-Labs API scale, the security grade of this interface is {}".format(endpoint["grade"]),
            "solution": "View the detailled findings",
            "type": "tls_ssllabs_grade",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "grade"],
                "links": [direct_link, "https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide"]
            },
            "raw": endpoint["grade"]
        })

    # certificate_keysize
    details = endpoint["details"]
    certificate_keysize = details["key"]["alg"] + " " + str(details["key"]["size"]) + " bits (strength = " + str(details["key"]["strength"]) + " bits)"
    nb_vulns['info'] += 1
    issues.append({
        "issue_id": len(issues)+1,
        "severity": "info", "confidence": "certain",
        "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
        "title": "Certificate Key = {}".format(certificate_keysize),
        "description": "The provided certificate use a {} key".format(certificate_keysize),
        "solution": "n/a",
        "type": "tls_certificate_keysize",
        "timestamp": ts,
        "metadata": {
            "tags": ["ssl", "certificate", "tls", "key", "keysize"],
            "links": [direct_link]
        },
        "raw": details["key"]
    })

    # certificate_debianflaw
    if "debianFlaw" in details["key"].keys() and details["key"]["debianFlaw"] is True:
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "Certificate using a flawed key (bad SSL/SSH Debian keys)",
            "description": "The provided certificate use a flawed key. See https://www.debian.org/security/2008/dsa-1571",
            "type": "tls_certificate_debianflaw",
            "solution": "Renew the RSA keys",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "key", "debian"],
                "links": [direct_link]
            },
            "raw": details["key"]
        })

    # supported_protocols
    protocols = [p["name"]+"/"+p["version"]for p in list(details["protocols"])]
    nb_vulns['info'] += 1
    issues.append({
        "issue_id": len(issues)+1,
        "severity": "info", "confidence": "certain",
        "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
        "title": "Supported SSL/TLS protocols: {}".format(", ".join(protocols)),
        "description": "Following protocols are accepted on '{}' : {}".format(
            asset_name, ", ".join(protocols)),
        "type": "tls_supported_protocols",
        "solution": "n/a",
        "timestamp": ts,
        "metadata": {
            "tags": ["ssl", "certificate", "tls", "protocol", "version"],
            "links": [direct_link]
        },
        "raw": details["protocols"]
    })

    for protocol in list(details["protocols"]):
        if protocol["name"] == "SSL":
            nb_vulns['high'] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "high", "confidence": "certain",
                "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
                "title": "Non-secure SSL/TLS protocol supported: {}".format(protocol["name"]+"/"+protocol["version"]),
                "description": "Multiple vulnerabilities has been found on the '{}' protocol implementation".format(protocol["name"]+"/"+protocol["version"]),
                "type": "tls_supported_protocols",
                "solution": "Disable the protocol " + protocol['name'] + " in the SSL/TLS server configuration",
                "timestamp": ts,
                "metadata": {
                    "tags": ["ssl", "certificate", "tls", "protocol"],
                    "links": [direct_link]
                },
                "raw": details["protocols"]
            })

    # accepted_ciphersuites
    # for suite in list(details["suites"]["list"]):
    #     nb_vulns['info'] += 1
    #     issues.append({
    #         "issue_id": len(issues)+1,
    #         "severity": "info", "confidence": "certain",
    #         "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
    #         "title": "Ciphersuite supported: {}".format(suite["name"]),
    #         "description": "The ciphersuite {} is accepted for securing SSL/TLS communication (cipherStrength={})".format(suite["name"], suite["cipherStrength"]),
    #         "type": "tls_accepted_ciphersuites",
    #         "solution": "n/a",
    #         "timestamp": ts,
    #         "metadata": {
    #             "tags": ["ssl", "certificate", "tls", "ciphersuites"]
    #        },
    #         "raw": details["suites"]["list"]
    #    })

    ciphersuites_str = ""
    for suite in list(details["suites"]["list"]):
        ciphersuites_str = "".join((ciphersuites_str, "{} (Strength: {})\n".format(suite["name"], suite["cipherStrength"])))
    ciphersuites_hash = hashlib.sha1(str(ciphersuites_str).encode('utf-8')).hexdigest()[:6]
    nb_vulns['info'] += 1
    issues.append({
        "issue_id": len(issues)+1,
        "severity": "info", "confidence": "certain",
        "target": {"addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
        "title": "Supported ciphersuites for '{}' (#: {}, HASH: {})".format(asset_name, len(details["suites"]["list"]), ciphersuites_hash),
        "description": "The following ciphersuites are accepted for securing SSL/TLS communication: \n{}".format(ciphersuites_str),
        "type": "tls_accepted_ciphersuites",
        "solution": "n/a",
        "timestamp": ts,
        "metadata": {
            "tags": ["ssl", "certificate", "tls", "ciphersuites"],
            "links": [direct_link]
        },
        "raw": details["suites"]["list"]
    })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"]
    }

    return issues, summary


@app.before_first_request
def main():
    if not os.path.exists(APP_BASE_DIR+'/ssllabs.json'):
        app.logger.error("Error: config file '{}' not found".format(APP_BASE_DIR+'/ssllabs.json'))
        sys.exit(4)

    # Check if the results folder exists
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
