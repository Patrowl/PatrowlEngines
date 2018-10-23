#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, requests, json, datetime, time, hashlib, optparse, copy, logging
from urlparse import urlparse
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5004
APP_MAXSCANS = 10

DEFAULT_API_URL = "https://api.ssllabs.com/api/v2/"

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scans = {}
requests.packages.urllib3.disable_warnings()

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

'''
# inputs:
{"assets": [{
    "id" :'3',
    "value" :'8.8.8.8',
    "criticity": 'low',
    "datatype": 'ip'
    }, {...}],
 "options": {
    "ports": '443',
    "max_timeout": 3600
    }
 }

# outputs:
{"page": "report",
"scan_id": 86a5f993-30c2-47b7-a401-c4ae7e2a1e57,
"status": "success",
"issues": [{
    "issue_id": 1,
    "severity": 'info',
    "confidence": 'certain',
    "target": {
        "addr": 8.8.8.8,
        "port_id": "443",
        "port_type": 'tcp'
    },
    "title": 'sss',
    "description": 'sss',
    "type": 'ssl_protocols',
    "timestamp": 143545645775
}]}

'''

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


def _loadconfig():
    conf_file = BASE_DIR+'/ssllabs.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        if not "api_url" in this.scanner.keys() or this.scanner["api_url"] == "":
            this.scanner["api_url"] = DEFAULT_API_URL

        try:
            r = requests.get(url=this.scanner['api_url'] + 'info', verify=False)
            if r.status_code == 200:
                this.scanner['status'] = 'READY'
            else:
                this.scanner['status'] = 'ERROR'
        except:
            this.scanner['status'] = 'ERROR'

        return { "status": this.scanner['status']}
    else:
        print("Error: config file '{}' not found".format(conf_file))
        return { "status": "error", "reason": "config file not found", "details": {
            "filename": conf_file
        }}


@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/ssllabs/')
def index():
    return jsonify({ "page": "index" })


@app.route('/engines/ssllabs/clean', methods=['GET'])
def clean():
    res = { "page": "clean" }
    this.scans = {}
    _loadconfig()
    res.update({ "status": "SUCCESS" })
    return jsonify(res)


@app.route('/engines/ssllabs/clean/<scan_id>', methods=['GET'])
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/ssllabs/reloadconfig', methods=['GET'])
def reloadconfig():
    res = { "page": "reloadconfig" }
    res.update(_loadconfig())
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/ssllabs/info', methods=['GET'])
def info():
    res = { "page": "info" }

    url = this.scanner['api_url'] + "info"
    try:
        r = requests.get(url=url, verify=False)
        if r.status_code == 200:
            res.update({ "engine_config": this.scanner })
            res['engine_config'].update(({"api_config": json.loads(r.text)}))

            res.update({ "status": "READY"})
        else:
            res.update({ "status": "ERROR", "details": {
                "engine_config": this.scanner }})
    except:
        res.update({ "status": "error", "details": "connexion error to the API {}".format(url)})

    return jsonify(res)

'''
    # Function 'status()'
    #   - display current status of the scanner: READY, ERROR
    #   - display the last 10 scans status: SCANNING, DONE, ERROR + scan_id + timestamp
'''
@app.route('/engines/ssllabs/status', methods=['GET'])
def status():
    res = { "page": "status" }
    # display the status of the scanner
    this.scanner['status'] = json.loads(info().get_data())['status']
    res.update({"status": this.scanner['status']})

    # display info on the scanner
    res.update({"scanner": this.scanner})

    # display the status of scans performed
    res.update({"scans": this.scans})

    return jsonify(res)


def _is_scan_finished(scan_id):
    if not scan_id in this.scans.keys():
        return False

    if this.scans[scan_id]["status"] == "FINISHED":
        return True

    all_scans_done = True
    try:
        for host in this.scans[scan_id]["hosts"]:
            r = requests.get(url=host["url"], verify=False)
            if r.status_code == 200 and json.loads(r.text)["status"] not in ["READY", "ERROR"]:
                all_scans_done = False

    except:
        print("API connexion error")
        return False

    if all_scans_done:
        this.scans[scan_id]["status"] = "FINISHED"
        this.scans[scan_id]["finished_at"] = datetime.datetime.now()
        return True

    return False

'''
    # Function 'scan_status(scan_id=86a5f993-30c2-47b7-a401-c4ae7e2a1e57)'
    #   - call the API to check status
    #   - display current status of the scan: SCANNING, DONE, ERROR
'''
@app.route('/engines/ssllabs/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    res = { "page": "scan_status" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # @todo: check id the scan is finished or not
    _is_scan_finished(scan_id)
    # try:
        # r = requests.get(url=this.scan['url'], verify=False)
        # if r.status_code != 200:
        #     res.update({ "status": "error", "reason": "something wrong with the API invokation"})
        #     return jsonify(res)
    # except:
    #   res.update({ "status": "error", "reason": "something wrong with the API invokation"})
    #   return jsonify(res)

    # return the scan parameters and the status
    res.update({"scan": this.scans[scan_id]})
    res.update({"status": this.scans[scan_id]["status"]})

    return jsonify(res)


@app.route('/engines/ssllabs/startscan', methods=['POST'])
def start():
    res = { "page": "startscan"}
    scan = {}

    data = json.loads(request.data)

    # Check assets
    if not 'assets' in data.keys() or not'scan_id' in data.keys():
		res.update({
			"status": "error",
			"reason": "arg error, something is missing (ex: 'assets', 'scan_id')"
		})
		return jsonify(res)

    valid_assets = copy.deepcopy(data["assets"])
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
			# res.update({
    		# 	"status": "error",
    		# 	"reason": "arg error, something is missing ('asset.value')"
    		# })
			# return jsonify(res)
            valid_assets.remove(asset)

        # Supported datatypes
        if asset["datatype"] not in this.scanner["allowed_asset_types"]:
            # res.update({
    		# 	"status": "error",
    		# 	"reason": "arg error, bad value for '{}' datatype (not supported)".format(asset["value"])
    		# })
            # return jsonify(res)
            valid_assets.remove(asset)

        # url transform
        if asset["datatype"] == 'url':
            #data[asset]["value"] = "{uri.netloc}".format(uri=urlparse(asset["value"]))
            valid_assets.remove(asset)
            valid_assets.append({
                "id": asset["id"],
                "datatype": asset["datatype"],
                "criticity": asset["criticity"],
                "value": "{uri.netloc}".format(uri=urlparse(asset["value"]))
                })

    # print "data['assets']:", data["assets"]
    # print "valid_assets:", valid_assets
    # Check scan_id
    scan["scan_id"] = str(data["scan_id"])
    if data["scan_id"] in this.scans.keys():
        res.update({ "status": "error", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    # Initialize the scan parameters
    if not 'ports' in data['options'].keys():
        scan["target_port"] = "443"
        #scan_ports = "443"
    else:
        scan["target_port"] = str(list(data['options']['ports'])[0]) # get the 1st in list
        #scan_ports = str(list(data['options']['ports'])[0]) # get the 1st in list

    scan["hosts"] = []
    #for asset in data['assets']:
    for asset in valid_assets:
        if asset["value"] not in [h["host"] for h in scan["hosts"]]:
            target_host = asset["value"]
            target_url = "{}analyze?host={}&port={}&publish=off&ignoreMismatch=on&maxAge=2&fromCache=on".format(this.scanner['api_url'], target_host, scan["target_port"])
            scan["hosts"].append({"host": target_host, "url": target_url})

    # scan["target_host"] = str(list(data['assets'])[0]["value"]) # get the 1st in list
    #
    # scan["url"] = this.scanner['api_url'] + "analyze?host=" + scan["target_host"] + "&port=" + scan["target_port"]
    # scan["url"] += "&publish=off&ignoreMismatch=on&maxAge=2&fromCache=on"
    scan["started_at"] = datetime.datetime.now()

    # Start the scans for each hosts
    try:
        for host in scan["hosts"]:
            r = requests.get(url=host["url"], verify=False)
            if r.status_code == 200:
                res.update({ "status": "accepted"})
                scan["status"] = "SCANNING"
            else:
                res.update({ "status": "error", "reason": "something wrong with the API invokation"})
                scan["status"] = "ERROR"
                scan["finished_at"] = datetime.datetime.now()
    except:
        res.update({ "status": "error", "reason": "connexion error"})
        scan["status"] = "ERROR"
        scan["finished_at"] = datetime.datetime.now()

    # Prepare data returned
    this.scans.update({scan["scan_id"]: scan})
    res.update({"scan": scan})

    return jsonify(res)


# Stop all scans
@app.route('/engines/ssllabs/stopscans', methods=['GET'])
def stop():
    res = { "page": "stopscans" }

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({ "status": "SUCCESS" })

    return jsonify(res)


@app.route('/engines/ssllabs/stop/<scan_id>', methods=['GET'])
def stop_scan(scan_id):
    res = { "page": "stopscan" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans[scan_id]["status"] = "STOPPED"
    this.scans[scan_id]["finished_at"] = datetime.datetime.now()

    return jsonify(res)

'''
# outputs:
{"page": "report",
"scan_id": 1212,
"status": "success",
"issues": [{
    "issue_id": 1,
    "severity": 'info',
    "confidence": 'certain',
    "asset": {
        "addr": 8.8.8.8,
        "port_id": "443",
        "port_type": 'tcp'
    },
    "title": 'sss',
    "description": 'sss',
    "type": 'ssl_protocols',
    "timestamp": 143545645775
}]}
'''
@app.route('/engines/ssllabs/getfindings/<scan_id>')
def getfindings(scan_id):
    res = { "page": "getfindings" , "scan_id": scan_id}

    if not _is_scan_finished(scan_id):
        res.update({ "status": "error", "reason": "scan '{}' not finished".format(scan_id)})
        return jsonify(res)

    scan = this.scans[scan_id]
    port = scan['target_port']
    issues = []
    summary = {}
    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0}

    for host in scan["hosts"]:
        try:
            r = requests.get(url=host["url"]+"&all=done", verify=False)
            if r.status_code != 200:
                res.update({ "status": "error", "reason": "something wrong with the API invokation"})
                return jsonify(res)
        except:
            res.update({ "status": "error", "reason": "something wrong with the API invokation"})
            return jsonify(res)

        tmp_issues, tmp_summary = _parse_report(results=json.loads(r.text), asset_name=host["host"], asset_port=port)
        issues = issues + tmp_issues
        nb_vulns["info"] = nb_vulns["info"] + tmp_summary["nb_info"]
        nb_vulns["low"] = nb_vulns["low"] + tmp_summary["nb_low"]
        nb_vulns["medium"] = nb_vulns["medium"] + tmp_summary["nb_medium"]
        nb_vulns["high"] = nb_vulns["high"] + tmp_summary["nb_high"]

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "ssllabs",
        "engine_version": this.scanner["version"]
    }

    #Store the findings in a file
    with open(BASE_DIR+"/results/ssllabs_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": this.scans[scan_id],
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
    }
    ts = int(time.time() * 1000)
    if results["status"] == "ERROR":
        issues.append({
            "issue_id": 1,
            "severity": "info", "confidence": "certain",
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "nb_high": 0
        }

        return issues, summary

    endpoint = results["endpoints"][0]
    asset_ipaddr = str(endpoint['ipAddress'])


    # Check results
    if len(endpoint['details']['protocols']) == 0:
        nb_vulns['info'] += 1
        issues.append({
            "issue_id": 1,
            "severity": "info", "confidence": "certain",
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
            "title": "Failed to communicate with the secure server.",
            "description": "Failed to communicate with the secure server.",
            "solution": "Check the availability of the asset.",
            "type": "tls_access",
            "timestamp": ts,
            "metadata": {
                "tags": ["ssl", "certificate", "tls", "availability"]
            },
            "raw": endpoint["details"]
        })

        summary = {
            "nb_issues": 1,
            "nb_info": 1,
            "nb_low": 0,
            "nb_medium": 0,
            "nb_high": 0
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
        "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
    if "debianFlaw" in details["key"].keys() and details["key"]["debianFlaw"] == True:
        nb_vulns['high'] += 1
        issues.append({
            "issue_id": len(issues)+1,
            "severity": "high", "confidence": "certain",
            "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
        "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
        "title": "Supported SSL/TLS protocols: {}".format(", ".join(protocols)),
        "description": "Following protocols are accepted on '{}' : {}".format(asset_name, ", ".join(protocols)),
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
                "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
    #         "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
    #         "title": "Ciphersuite supported: {}".format(suite["name"]),
    #         "description": "The ciphersuite {} is accepted for securing SSL/TLS communication (cipherStrength={})".format(suite["name"], suite["cipherStrength"]),
    #         "type": "tls_accepted_ciphersuites",
    #         "solution": "n/a",
    #         "timestamp": ts,
    #         "metadata": {
    #             "tags": ["ssl", "certificate", "tls", "ciphersuites"]
    #         },
    #         "raw": details["suites"]["list"]
    #     })

    ciphersuites_str = ""
    for suite in list(details["suites"]["list"]):
        ciphersuites_str  = "".join((ciphersuites_str, "{} (Strength: {})\n".format(suite["name"], suite["cipherStrength"])))
    ciphersuites_hash = hashlib.sha1(ciphersuites_str).hexdigest()[:6]
    nb_vulns['info'] += 1
    issues.append({
        "issue_id": len(issues)+1,
        "severity": "info", "confidence": "certain",
        "target": { "addr": [asset_name], "port_id": asset_port, "port_type": 'tcp'},
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
        #"engine_name": "ssllabs",
        #"engine_version": this.scanner["version"]
    }

    return issues, summary


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


@app.route('/engines/ssllabs/getreport/<scan_id>')
def getreport(scan_id):
    filepath = BASE_DIR+"/results/ssllabs_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_from_directory(BASE_DIR+"/results/", "ssllabs_"+scan_id+".json")

@app.route('/engines/ssllabs/test')
def test():
    if not APP_DEBUG:
        return jsonify({"page": "test"})

    res = "<h2>Test Page (DEBUG):</h2>"
    import urllib
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urlparse.unquote("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+'/ssllabs.json'):
        app.logger.error("Error: config file '{}' not found".format(BASE_DIR+'/ssllabs.json'))
        sys.exit(4)

    # Check if the results folder exists
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option(
        "-H", "--host", default=APP_HOST,
        help="Hostname of the Flask app [default %s]" % APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
