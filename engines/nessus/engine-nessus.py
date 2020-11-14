#!/usr/bin/python3
# -*- coding: utf-8 -*-

from nessrest import ness6rest, credentials
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import os
import sys
import json
import requests
import time
import datetime
import optparse
import logging

# Import local report parser
from parser import parse_report


app = Flask(__name__)
APP_DEBUG = os.environ.get('APP_DEBUG', '').lower() in ['true', '1', 'on', 'yes']
APP_HOST = "0.0.0.0"
APP_PORT = 5002
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 20))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = BASE_DIR + '/tmp'
POLICY_FOLDER = BASE_DIR + '/etc'
this = sys.modules[__name__]
this.nessscan = None
this.scanner = {}
this.scans = {}


if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/nessus/')
def index():
    return jsonify({"page": "index"})


def _loadconfig():
    conf_file = BASE_DIR+'/nessus.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        os.environ['NO_PROXY'] = this.scanner["server_host"]
    else:
        app.logger.debug("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "details": {"reason": "config file not found"}}

    try:
        # Check authentication methods (login/pass vs. api)
        if 'access_key' in this.scanner.keys() and 'secret_key' in this.scanner.keys():
            this.nessscan = ness6rest.Scanner(
                url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
                api_akey=this.scanner['access_key'],
                api_skey=this.scanner['secret_key'],
                insecure=True)
        elif 'server_username' in this.scanner.keys() and 'server_password' in this.scanner.keys():
            this.nessscan = ness6rest.Scanner(
                url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
                login=this.scanner['server_username'],
                password=this.scanner['server_password'],
                insecure=True)
        if this.nessscan.res['scanners'][0]['status'] == "on":
            return {"status": "success"}
        else:
            return {
                "status": "error",
                "details": {"reason": "connection error to Nessus instance (bad credz? not available ?)"}
            }
    except Exception:
        return {
            "status": "error",
            "details": {"reason": "connection error to Nessus instance (bad credz? not available ?)"}
        }


@app.route('/engines/nessus/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/nessus/_upload_policy', methods=['POST'])
def _upload_policy():
    res = {"page": "_upload_policy"}

    # @TODO

    return jsonify(res)


@app.route('/engines/nessus/_get_scanlist')
def _get_scanlist():
    res = {	"page": "_get_scanlist"}

    this.nessscan.action(action="scans", method="GET")
    scan_list = [scan for scan in this.nessscan.res['scans']]

    res.update({"status": "success", "details": {"scan_list": scan_list}})
    return jsonify(res)


@app.route('/engines/nessus/getfindings/<scan_id>/<nessus_scan_id>')
def getfindings(scan_id,nessus_scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}
    scan_id = str(scan_id)
    nessus_scan_id = str(nessus_scan_id)

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    time.sleep(3)

    # Check the scan status
    #scan_status(scan_id,nessus_scan_id)
    if this.scans[scan_id]['status'] not in ['FINISHED', 'STOPPED']:
        res.update({"status": "error", "reason": "scan_id '{}' not finished".format(scan_id)})
        return jsonify(res)

    nessscan_id = str(this.scans[scan_id]["nessscan_id"])
    if this.scans[scan_id]['nessus_scan_hid'] is not None:
        this.nessscan.action(action="scans/"+nessscan_id+"?history_id="+this.scans[scan_id]['nessus_scan_hid'], method="GET")
    else:
        this.nessscan.action(action="scans/"+nessscan_id, method="GET")

    ######
    report_content = this.nessscan.download_scan(
        export_format='nessus',
        history_id=this.scans[scan_id]['nessus_scan_hid'],
        scan_id=nessscan_id)
    report_filename = "{}/reports/nessus_{}_{}.nessus".format(
        BASE_DIR, scan_id, int(time.time()))
    with open(report_filename, 'wb') as w:
        w.write(report_content)

    nessus_prefix = "https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port'])
    # Check if FQDN shoud be resolved (default=false)
    resolve_fqdn = False
    if 'identifybyfqdn' in this.scans[scan_id]['options'].keys() and this.scans[scan_id]['options']['identifybyfqdn'] is True:
        resolve_fqdn = True
    block_summary, block_issues = parse_report(report_filename, nessus_prefix, resolve_fqdn)
    ######

    # Store the findings in a file
    with open(BASE_DIR+"/results/nessus_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": this.scans[scan_id],
            "summary": block_summary,
            "issues": block_issues
        }, report_file, default=_json_serial)

    res.update({
        "status": "success",
        "summary": block_summary,
        "issues": block_issues
    })
    # Remove the scan from the active scan list
    clean_scan(scan_id)

    return jsonify(res)


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


@app.route('/engines/nessus/getreport/<scan_id>')
def getreport(scan_id):
    scan_id = str(scan_id)
    filepath = BASE_DIR+"/results/nessus_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({
            "status": "error",
            "reason": "report file for scan_id '{}' not found".format(scan_id)}
        )

    return send_from_directory(BASE_DIR+"/results/", "nessus_"+scan_id+".json")


def allowed_file(filename):
    # here the checks (size, format, ...)
    return True


@app.route('/engines/nessus/_get_custom_policy', methods=['POST'])
def _get_custom_policy():
    res = {"page": "_get_custom_policy"}
    # check if the post request has the file part
    if 'file' not in request.files:
        res.update({"status": "error", "reason": "No file uploaded"})
        return jsonify(res)
    file = request.files['file']
    if file.filename == '':
        res.update({"status": "error", "reason": "No file selected"})
        return jsonify(res)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) + '_' + str(int(time.time()))
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # remainder: purge the custom policy file?
        res.update({"status": "success", "details": {"filename": filename}})
        return jsonify(res)
    res.update({"status": "error", "reason": "undefined"})
    return jsonify(res)


@app.route('/engines/nessus/_get_local_policy', methods=['GET'])
def _get_local_policy(policy=None):
    res = {"page": "_get_local_policy"}
    if not policy and not request.args.get('policy'):
        res.update({"status": "error", "reason": "'policy' arg is missing"})
        return jsonify(res)
    if not policy:
        policy = request.args.get('policy')
    policy_filename = POLICY_FOLDER + '/' + policy

    if not os.path.exists(policy_filename):
        res.update({
            "status": "error",
            "reason": "policy file not found",
            "details": {"filename": policy_filename, "name": policy}})
    else:
        res.update({
            "status": "success",
            "details": {"filename": policy_filename, "name": policy}})
    return jsonify(res)


def _get_credentials(credz):
    format_credentials = []
    for cred in credz:
        if 'type' not in cred.keys():
            continue
        elif cred['type'] == "windows_password":
            if 'username' in cred.keys() and 'password' in cred.keys():
                win_domain = ""
                if 'domain' in cred.keys():
                    win_domain = cred['domain']
                format_credentials.append(credentials.WindowsPassword(
                    username=cred['username'],
                    password=cred['password'],
                    domain=win_domain
                ))
        elif cred['type'] == "ssh_password":
            if 'username' in cred.keys() and 'password' in cred.keys():
                format_credentials.append(credentials.SshPassword(
                    username=cred['username'],
                    password=cred['password']
                ))
        # elif cred['type'] == "ssh_publickey":
        #     pass
        # @Todo
    return format_credentials


@app.route('/engines/nessus/startscan', methods=['POST'])
def start_scan():
    # @todo: validate parameters and options format
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "details": {
                "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
            }
        })
        return jsonify(res)

    status()
    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": this.scanner['status']
        }})
        return jsonify(res)

    scan = {}

    # Parse the args in POST
    post_args = json.loads(request.data)
    scan_id = str(post_args['scan_id'])

    # Check assets
    allowed_assets = []
    for asset in post_args['assets']:
        if asset["datatype"] in this.scanner["allowed_asset_types"]:
            # extract the net location from urls
            if asset["datatype"] == 'url':
                asset["value"] = "{uri.netloc}".format(uri=urlparse(asset["value"]))
            allowed_assets.append(asset["value"].strip())
    assets = ",".join(allowed_assets)

    # Initialize history_id
    nessus_scan_hid = None

    # Check action
    if 'action' not in post_args['options'].keys():
        res.update({
            "status": "error",
            "details": {"reason": "Missing action ('scan', 'getreports', ...)"}
        })
        return jsonify(res)

    if post_args['options']['action'] == 'getreports':
        # Search form policies
        scan_name = post_args['options']['name']
        if not this.nessscan.scan_exists(scan_name):
            res.update({
                "status": "error",
                "details": {"reason": "Scan '{}' does not exist.".format(scan_name)}
            })
            return jsonify(res)

        # Get scan details
        #always get the last completed report . The last report has the max id.
        wanted_scan=[]
        scan_list = this.nessscan.scan_list()
        for item in scan_list["scans"]:
            if item["name"]==scan_name and item["status"]=="completed":
                wanted_scan.append(int(item["id"]))
        nessus_scan_id=max(wanted_scan)
        for item in scan_list["scans"]:
            if item["id"]==nessus_scan_id and item["status"]=="completed":
                wanted_uuid=item["uuid"]

        # Update the scan info
        this.scans.update({
            scan_id: {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "nessscan_id": nessus_scan_id,
                "nessus_scan_hid": '',
                "nessscan_uuid": wanted_uuid,
                "options": post_args['options'],
                "assets": post_args['assets'],
                "status": "STARTED",
                "started_at": int(time.time() * 1000),
                "findings": {}
            }
        })
        res.update({"status": "accepted", "details": scan, "nessscan_id": str(nessus_scan_id)})

    if post_args['options']['action'] == 'scan':
        # Check scan policy
        if 'policy' not in post_args['options'].keys():
            res.update({
                "status": "error",
                "reason": "Missing policy name"})
            return jsonify(res)

        policy_name = post_args['options']['policy'].split(".nessus")[0]
        # Check the policy is already uploaded to the scanner
        # Todo
        # tmp_res = requests.post(url_for('_get_custom_policy'), data=request.data)

        # # joke.begin() -- makeitbeautifly()
        # s = str(tmp_res.response)
        # s = s.replace('\\n','').replace(' ','').replace('(','').replace('\'','')
        # s = json.loads(s[:len(s)-2])
        # # joke.end()

        # if s['status'] == "error":
        #     res.update({"status": "error", "reason": "error with the policy"})
        #     return jsonify(res)
        #
        # policy_name = s['details']['name'].split(".nessus")[0]

        # if not this.nessscan.policy_exists(name=policy_name):
        #     this.nessscan.upload(upload_file=s['details']['filename'])
        #     this.nessscan.policy_import(filename=this.nessscan.res[u'fileuploaded'])

        # Set the scan policy
        try:
            this.nessscan.policy_set(name=policy_name)
        except SystemExit:
            res.update({
                "status": "error",
                "reason": "Bad policy name: {}".format(policy_name)})
            return jsonify(res)

        this.nessscan.policy_set(name=policy_name)
        this.nessscan.action(
            action="policies/" + str(this.nessscan.policy_id),
            method="put")

        # Add credentials (if any)
        if 'credentials' in post_args['options'].keys():
            credz = _get_credentials(post_args['options']['credentials'])
            this.nessscan.policy_copy(
                existing_policy_name=policy_name,
                new_policy_name=policy_name + "-" + scan_id)
            this.nessscan.policy_add_creds(credz)

        # Create the scan
        this.nessscan.scan_add(
            targets=assets,
            name="[TO] Nessus Scan - {} ({})".format(scan_id, int(time.time())),
        )

        nessscan_id = this.nessscan.res["scan"]["id"]
        nessscan_name = this.nessscan.res["scan"]["name"]

        this.nessscan.scan_run()

        this.scans.update({
            scan_id: {
                "scan_id": scan_id,
                "scan_name": nessscan_name,
                "nessscan_id": nessscan_id,
                "nessus_scan_hid": nessus_scan_hid,
                "nessscan_uuid": this.nessscan.res['scan_uuid'],
                "options": post_args['options'],
                "policy_name": policy_name,
                "assets": post_args['assets'],
                "status": "STARTED",
                "started_at": int(time.time() * 1000),
                "findings": {}
            }
        })
        res.update({"status": "accepted", "details": scan, "nessscan_id": str(nessscan_id)})
    return jsonify(res)


@app.route('/engines/nessus/stop/<scan_id>/<nessus_scan_id>', methods=['GET'])
def stop_scan(scan_id,nessus_scan_id):
    res = {"page": "stopscan"}
    scan_id = str(scan_id)
    nessus_scan_id = str(nessus_scan_id)

    #scan_status(scan_id, nessus_scan_id)
    if this.scans[scan_id]['status'] in ['SCANNING']:
        this.nessscan.action(
            action="scans/"+str(nessus_scan_id)+"/stop",
            method="POST")

    if this.nessscan.res != {}:
        res.update({"status": "error", "reason": this.nessscan.res['error']})
        return jsonify(res)

    this.scans[scan_id].update({
        "status": "STOPPED",
        "finished_at": int(time.time() * 1000)
    })

    res.update({"status": "success", "scan": this.scans[scan_id]})
    return jsonify(res)


@app.route('/engines/nessus/stopscans', methods=['GET'])
def stop():
    res = {"page": "stopscans"}

    for scan_id in this.scans.keys():
        clean_scan(scan_id)

    res.update({"status": "success", "details": {
        "timestamp": int(time.time())}})
    return jsonify(res)


@app.route('/engines/nessus/clean', methods=['GET'])
def clean():
    res = {"page": "clean"}
    this.scans.clear()
    _loadconfig()
    return jsonify(res)


@app.route('/engines/nessus/clean/<scan_id>', methods=['GET'])
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    scan_id = str(scan_id)
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({
            "status": "error",
            "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/nessus/status', methods=['GET'])
def status():
    res = {'page': 'status', "scans": this.scans}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
        res.update({
            "status": "BUSY",
            "reason": "Max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)

    # check if the remote service is available
    try:
        scan = {}
        # scan = ness6rest.Scanner(
        #     url="https://{}:{}".format(
        #         this.scanner['server_host'], this.scanner['server_port']),
        #     login=this.scanner['server_username'],
        #     password=this.scanner['server_password'],
        #     insecure=True)
        if 'access_key' in this.scanner.keys() and 'secret_key' in this.scanner.keys():
            scan = ness6rest.Scanner(
                url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
                api_akey=this.scanner['access_key'],
                api_skey=this.scanner['secret_key'],
                insecure=True)
        elif 'server_username' in this.scanner.keys() and 'server_password' in this.scanner.keys():
            scan = ness6rest.Scanner(
                url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
                login=this.scanner['server_username'],
                password=this.scanner['server_password'],
                insecure=True)
        if 'status' in scan.res.keys():
            this.scanner['status'] = "READY"
            res.update({
                'status': 'READY',
                'details': {
                    'server_host': this.scanner['server_host'],
                    'server_port': this.scanner['server_port'],
                    'status': scan.res['status']
                }
            })
        elif scan.res['scanners'][0]['status'] == "on":
            this.scanner['status'] = "READY"
            res.update({
                'status': 'READY',
                'details': {
                    'server_host': this.scanner['server_host'],
                    'server_port': this.scanner['server_port'],
                    'engine_version': scan.res['scanners'][0]['engine_version'],
                    'engine_build': scan.res['scanners'][0]['engine_build'],
                    'scan_count': scan.res['scanners'][0]['scan_count']
                }
            })
        else:
            this.scanner['status'] = "ERROR"
            res.update({'status': 'ERROR', 'details': {'reason': 'Nessus engine not available'}})
    except Exception:
        this.scanner['status'] = "ERROR"
        res.update({'status': 'ERROR', 'details': {'reason': 'Nessus engine not available'}})
    return jsonify(res)


@app.route('/engines/nessus/status/<scan_id>/<nessus_scan_id>', methods=['POST'])
def scan_status(scan_id,nessus_scan_id):
    scan_id = str(scan_id)
    nessus_scan_id = str(nessus_scan_id)
    post_args = json.loads(request.data)

    this.scans.update({
        scan_id: {
            "scan_id": scan_id,
        }})

    try:
        this.nessscan.action(
            action="scans/"+nessus_scan_id,
            method="GET")

        scan_status = this.nessscan.res
        nessus_scan_hid = None
        # create the dictionary with the required info.
        this.scans[scan_id]['nessscan_id'] = this.nessscan.res["info"]["object_id"]
        this.scans[scan_id]['nessscan_uuid'] = this.nessscan.res['info']['uuid']
        this.scans[scan_id]['policy_name'] = this.nessscan.res['info']['policy']
        this.scans[scan_id]['options'] = post_args
        this.scans[scan_id]['started_at'] = this.nessscan.res['info']['scanner_start']
        this.scans[scan_id]['nessus_scan_hid'] = nessus_scan_hid
        nessus_scan_status = 'unknown'
        if 'info' in scan_status.keys():
            nessus_scan_status = this.nessscan.res['info']['status']
        elif 'status' in scan_status.keys():
            nessus_scan_status = scan_status['status']

        if nessus_scan_status == 'completed':
            this.scans[scan_id]['status'] = "FINISHED"
        elif nessus_scan_status in ['running', 'loading']:
            this.scans[scan_id]['status'] = "SCANNING"
        elif nessus_scan_status == 'canceled':
            this.scans[scan_id]['status'] = "STOPPED"
        else:
            this.scans[scan_id]['status'] = nessus_scan_status.upper()

    except Exception:
        this.scans[scan_id]['status'] = "ERROR"

    return jsonify({
        "status": this.scans[scan_id]['status'],
        "scan": this.scans[scan_id]})


def _without_keys(d, keys):
    return {x: d[x] for x in d if x not in keys}


@app.route('/engines/nessus/info')
def info():
    secret_fields = ["access_key", "secret_key", "server_password"]
    return jsonify({
        "page": "info",
        "engine_config": _without_keys(this.scanner, secret_fields)})


@app.route('/engines/nessus/genreport', methods=['GET'])
def genreport(scan_id=None, report_format="html"):
    res = {"page": "genreport"}
    scan_id = str(scan_id)

    if scan_id not in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": {"reason": "scan_id '{}' not found".format(scan_id)}})

    this.nessscan.action(action="scans", method="GET")
    scan_status = None
    for scan in this.nessscan.res['scans']:
        if scan['id'] == int(scan_id):
            scan_status = "found"
    if not scan_status:
        res.update({"status": "error", "details": {"reason": "'scan_id={}' not found".format(scan_id)}})
        return jsonify(res)

    post_data = {"format": report_format}
    if report_format == "html":
        post_data.update({"chapters": "vuln_by_host"})

    ness_export_url = "scans/{}/export".format(scan_id)
    if this.scans[scan_id]['nessus_scan_hid'] is not None:
        ness_export_url += "?history_id=" + this.scans[scan_id]['nessus_scan_hid']
    this.nessscan.action(action=ness_export_url, method="POST", extra=post_data)

    res.update({"status": "success", "details": {
        "timestamp": int(time.time()),
        "scan_id": scan_id,
        "format": report_format,
        "token": this.nessscan.res['token'],
        "file": this.nessscan.res['file'],
        "url": "https://{}:{}/scans/exports/{}/download".format(
            this.scanner['server_host'],
            this.scanner['server_port'],
            this.nessscan.res['token'])
    }})
    return jsonify(res)


@app.route('/engines/nessus/getrawreports/<scan_id>', methods=['GET'])
def getrawreports(scan_id=None, report_format="html"):
    REPORT_FORMATS = ['html', 'csv', 'nessus']  # 'db' format not supported
    res = {"page": "getreport"}
    scan_id = str(scan_id)

    if not scan_id and not request.args.get("scan_id"):
        res.update({"status": "error", "details": {"reason": "'scan_id' arg is missing"}})
        return jsonify(res)

    if not scan_id and request.args.get("scan_id"):
        scan_id = request.args.get("scan_id")

    if request.args.get("format") in REPORT_FORMATS:
        report_format = request.args.get("format")

    this.nessscan.action(action="scans", method="GET")
    scan_status = None
    for scan in this.nessscan.res['scans']:
        if scan['id'] == int(scan_id):
            scan_status = "found"
            break
    if not scan_status:
        res.update({"status": "error", "details": {"reason": "'scan_id={}' not found".format(scan_id)}})
        return jsonify(res)

    post_data = {"format": report_format}
    if report_format == "html":
        post_data.update({"chapters": "vuln_by_host"})

    ness_export_url = "scans/{}/export".format(scan_id)
    if this.scans[scan_id]['nessus_scan_hid'] is not None:
        ness_export_url += "?history_id=" + this.scans[scan_id]['nessus_scan_hid']
    this.nessscan.action(action=ness_export_url, method="POST", extra=post_data)

    report_fileid = str(this.nessscan.res['file'])
    report_token = str(this.nessscan.res['token'])

    this.nessscan.action(
        action="scans/{}/export/{}/status".format(scan_id, report_fileid),
        method="GET"
    )
    if hasattr(this.nessscan.res, "status") and not this.nessscan.res['status'] == "ready":
        res.update({"status": "error", "details": {"reason": "report not available"}})
        return jsonify(res)

    tmp_filename = "nessus_{}_{}_{}.{}".format(scan_id, report_fileid, int(time.time()), report_format)
    with open(UPLOAD_FOLDER+'/'+tmp_filename, 'wb') as handle:
        report_url = "https://{}:{}/scans/exports/{}/download".format(this.scanner['server_host'], this.scanner['server_port'], report_token)
        response = requests.get(report_url, stream=True, verify=False)

        if not response.ok:
            res.update({"status": "error", "details": {"reason": "something got wrong in d/l"}})
            return jsonify(res)
        for block in response.iter_content(1024):
            handle.write(block)

    res.update({"status": "success", "details": {
        "timestamp": int(time.time()),
        "scan_id": scan_id,
        "format": report_format,
        "fileid": report_fileid,
        "token": report_token
    }})

    return jsonify(res)


@app.route('/engines/nessus/test', methods=['GET'])
def test():
    if not APP_DEBUG:
        return jsonify({"page": "test"})

    res = "<h2>Test Page (DEBUG):</h2>"
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
    return jsonify({
        "page": "undefined",
        "status": "error",
        "reason": "Page not found"
    })


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    if not os.path.exists(BASE_DIR+"/reports"):
        os.makedirs(BASE_DIR+"/reports")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option(
        "-H", "--host",
        help="Hostname of the Flask app [default %s]" % APP_HOST,
        default=APP_HOST)
    parser.add_option(
        "-P", "--port",
        help="Port for the Flask app [default %s]" % APP_PORT,
        default=APP_PORT)
    parser.add_option(
        "-d", "--debug",
        action="store_true",
        dest="debug",
        help=optparse.SUPPRESS_HELP,
        default=APP_DEBUG)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))