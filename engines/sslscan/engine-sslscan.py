#!/usr/bin/python
# -*- coding: utf-8 -*-
"""SSLScan PatrOwl engine application."""

import hashlib
import os
import sys
import subprocess
import threading
import time
from urlparse import urlparse
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
from flask_cors import CORS
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5014
APP_MAXSCANS = 25
APP_ENGINE_NAME = "sslscan"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)
CORS(app)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)


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


@app.route('/engines/sslscan/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/sslscan/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/sslscan/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/sslscan/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/sslscan/reloadconfig')
def reloadconfig():
    """Reload the configuration file."""
    return engine.reloadconfig()


@app.route('/engines/sslscan/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/sslscan/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/sslscan/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/sslscan/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/sslscan/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.getstatus_scan(scan_id)


@app.route('/engines/sslscan/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/sslscan/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/sslscan/getfindings/<scan_id>')
def getfindings(scan_id):
    """Get findings on finished scans."""
    return engine.getfindings(scan_id)


@app.route('/engines/sslscan/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


@app.route('/engines/sslscan/startscan', methods=['POST'])
def startscan():
    """Start a new scan."""
    # Check params and prepare the PatrowlEngineScan
    res = engine.init_scan(request.data)
    if "status" in res.keys() and res["status"] != "INIT":
        return jsonify(res)

    scan_id = res["details"]["scan_id"]

    if "ports" in engine.scans[scan_id]["options"].keys():
        asset_ports = engine.scans[scan_id]["options"]["ports"]
        if not isinstance(asset_ports, list):
            asset_ports = ["443"]
    else:
        asset_ports = ["443"]

    # Create the results folder
    if not os.path.exists(APP_BASE_DIR+"/results/"+scan_id):
        os.makedirs(APP_BASE_DIR+"/results/"+scan_id)

    assets_list = []
    for asset in engine.scans[scan_id]["assets"]:
        # @todo: Check if datatype is correct
        if asset["datatype"] not in engine.allowed_asset_types:
            continue
        if asset["datatype"] == "url":
            asset["value"] = urlparse(asset["value"]).netloc
        if asset["value"] not in assets_list:
            assets_list.append(asset["value"])

    for asset in assets_list:
        for asset_port in asset_ports:
            th = threading.Thread(
                target=_scan_thread,
                kwargs={
                    "scan_id": scan_id,
                    "asset": asset,
                    "asset_port": asset_port})
            th.start()
            engine.scans[scan_id]['threads'].append(th)

    engine.scans[scan_id]['status'] = "SCANNING"

    # Finish
    res.update({"status": "accepted"})
    return jsonify(res)


def _scan_thread(scan_id, asset, asset_port):
    # issue_id = 0
    # findings = []
    output_dir = APP_BASE_DIR+"/results/"+scan_id
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cmd = "{} --show-certificate --xml={}/{}.xml {}:{}".format(
        engine.options["bin_path"],
        output_dir, asset+"_"+asset_port, asset, asset_port)

    p = subprocess.Popen(cmd, shell=True, stdout=open("/dev/null", "w"))
    while p.poll() is None:
        # print("still running")
        time.sleep(1)
    engine.scans[scan_id]['status'] = "FINISHED"
    # print("done!!")
    _parse_xml_results(scan_id, asset, asset_port)


def _parse_xml_results(scan_id, asset, asset_port):
    issue_id = 0
    findings = []
    filename = APP_BASE_DIR+"/results/"+scan_id+"/"+asset+"_"+asset_port+".xml"
    # Check file
    try:
        findings_tree = ET.parse(filename)
    except Exception:
        print("No Element found in XML file: {}".format(filename))
        return False

    xml_root = findings_tree.getroot()
    scan_results = findings_tree.find("ssltest")

    # Finding: Scan details
    issue_id += 1
    new_finding = PatrowlEngineFinding(
        issue_id=issue_id,
        type="ssltest_scan_summary",
        title="SSLScan scan on '{}:{}'".format(asset, asset_port),
        description=ET.tostring(xml_root, encoding='utf-8', method='xml'),
        solution="n/a",
        severity="info",
        confidence="firm",
        raw=ET.tostring(xml_root, encoding='utf-8', method='xml'),
        target_addrs=[asset])
    findings.append(new_finding)

    # Finding: Supported ciphersuites
    issue_id += 1
    ciphersuites_issue = _get_ciphersuites(
        items=scan_results.findall("cipher"),
        issue_id=issue_id, asset=asset, asset_port=asset_port)
    if ciphersuites_issue:
        findings.append(ciphersuites_issue)

    # Finding: Certificate
    issue_id += 1
    certificate_pem_issue = _get_certificate_blob(
        cert_blob=scan_results.find("certificate").find("certificate-blob"),
        issue_id=issue_id, asset=asset, asset_port=asset_port)
    if certificate_pem_issue:
        findings.append(certificate_pem_issue)

    # Finding: Certificate is expired ?
    issue_id += 1
    is_cert_expired_issue = _is_certificate_expired(
        cert_tags=scan_results.find(".//certificate/expired/.."),
        issue_id=issue_id, asset=asset, asset_port=asset_port)
    if is_cert_expired_issue:
        findings.append(is_cert_expired_issue)

    # Finding: Certificate is self-signed ?
    issue_id += 1
    is_cert_selfsigned_issue = _is_certificate_selfsigned(
        cert_tags=scan_results.find(".//certificate/self-signed/.."),
        issue_id=issue_id, asset=asset, asset_port=asset_port)
    if is_cert_selfsigned_issue:
        findings.append(is_cert_selfsigned_issue)

    # Finding: Heartbleed
    issue_id += 1
    hb_vuln = _get_heartbleed_vuln(
        items=scan_results.findall("heartbleed"),
        issue_id=issue_id, asset=asset, asset_port=asset_port)
    if hb_vuln:
        findings.append(hb_vuln)

    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] += findings
    return True


def _get_heartbleed_vuln(items, issue_id, asset, asset_port):
    if items is None or not isinstance(items, list):
        return False

    is_vulnerable = False
    hb_links = ["http://heartbleed.com/"]
    hb_desc = ""

    for item in items:
        if item.get("vulnerable") == "1":
            hb_desc += "sslversion='{}' --> is VULNERABLE\n".format(
                item.get("sslversion"))
            is_vulnerable = True
        else:
            hb_desc += "sslversion='{}' --> is not vulnerable\n".format(
                item.get("sslversion"))

    if is_vulnerable:
        return PatrowlEngineFinding(
            issue_id=issue_id,
            type="ssltest_heartbleed",
            title="Heartbleed check on '{}:{}': VULNERABLE".format(
                asset, asset_port),
            description=hb_desc,
            solution="Update the version of the OpenSSL component used by the \
                service listening on port '{}'".format(asset_port),
            severity="high",
            confidence="firm",
            raw=hb_desc,
            target_addrs=[asset],
            meta_tags=["heartbleed", "ssl", "tls"],
            meta_links=hb_links,
            meta_vuln_refs=[{"CVE": ["CVE-2014-0160"]}])
    else:
        return PatrowlEngineFinding(
            issue_id=issue_id,
            type="ssltest_heartbleed",
            title="Heartbleed check on '{}:{}': not vulnerable".format(
                asset, asset_port),
            description=hb_desc,
            solution="n/a",
            severity="info",
            confidence="firm",
            raw=hb_desc,
            target_addrs=[asset],
            meta_tags=["heartbleed", "ssl", "tls"],
            meta_links=hb_links)


def _get_ciphersuites(items, issue_id, asset, asset_port):
    if items is None or not isinstance(items, list):
        return False

    issue_desc = "Supported ciphersuites:\n"
    for item in items:
        add_info = ""
        if 'curve' in item.keys():
            add_info += "Curve: ".format(item.get("curve"))
        if 'dhebits' in item.keys():
            add_info += "DHEbits: ".format(item.get("dhebits"))
        if 'ecdhebits' in item.keys():
            add_info += "ECDHEbits: ".format(item.get("ecdhebits"))
        issue_desc += "{:30} SSLVersion: {:8} Bits: {:4} Status: {:10} {}\n".format(
            item.get("cipher"), item.get("sslversion"),
            item.get("bits"), item.get("status"), add_info
        )

    return PatrowlEngineFinding(
        issue_id=issue_id,
        type="ssltest_supported_ciphersuites",
        title="Supported ciphersuites on '{}:{}'.".format(
            asset, asset_port),
        description=issue_desc,
        solution="n/a",
        severity="info",
        confidence="firm",
        raw=issue_desc,
        target_addrs=[asset],
        meta_tags=["ciphersuites", "ssl", "tls"])


def _get_certificate_blob(cert_blob, issue_id, asset, asset_port):
    if cert_blob is None:
        return False
    cert_hash = hashlib.sha1(cert_blob.text).hexdigest().upper()
    return PatrowlEngineFinding(
        issue_id=issue_id,
        type="ssltest_certificate_pem",
        title="Certificate was retrieved from '{}:{}' with hash '{}'.".format(
            asset, asset_port, cert_hash[:6]),
        description="Following certificate was retrieved from the server:\n\
            {}".format(cert_blob.text),
        solution="n/a",
        severity="info",
        confidence="firm",
        raw=cert_blob.text,
        target_addrs=[asset],
        meta_tags=["certificate", "ssl", "tls", "pem"])


def _is_certificate_expired(cert_tags, issue_id, asset, asset_port):
    if cert_tags is None:
        return False

    expired_text = cert_tags.find("expired").text
    if len(expired_text) == 0 or expired_text == "false":
        return False

    return PatrowlEngineFinding(
        issue_id=issue_id,
        type="ssltest_certificate_expired",
        title="Certificate from '{}:{}' is expired.".format(asset, asset_port),
        description="The SSL/TLS certificate retrieved from the server is \
            expired:\nNot valid before: {}\nNot valid after: {}".format(
            cert_tags.find("not-valid-before").text,
            cert_tags.find("not-valid-after").text),
        solution="Renew the certificate on the service listening on \
            '{}:{}'.".format(asset, asset_port),
        severity="high",
        confidence="firm",
        raw=expired_text,
        target_addrs=[asset],
        meta_tags=["certificate", "ssl", "tls", "expired"])


def _is_certificate_selfsigned(cert_tags, issue_id, asset, asset_port):
    if cert_tags is None:
        return False

    selfsigned_text = cert_tags.find("self-signed").text
    if len(selfsigned_text) == 0 or selfsigned_text == "false":
        return False

    return PatrowlEngineFinding(
        issue_id=issue_id,
        type="ssltest_certificate_selfsigned",
        title="Certificate from '{}:{}' is self-signed.".format(
            asset, asset_port),
        description="The SSL/TLS certificate retrieved from the server is \
            self-signed.",
        solution="Renew the certificate on the service listening on '{}:{}' \
            and sign it with a trusted CA.".format(asset, asset_port),
        severity="high",
        confidence="firm",
        raw=selfsigned_text,
        target_addrs=[asset],
        meta_tags=["certificate", "ssl", "tls", "self-signed"])


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")
    engine._loadconfig()

    # Check if sslscan is available
    if not os.path.isfile(engine.options["bin_path"]):
        sys.exit(-1)


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
