#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, subprocess, sys, json, requests, time, urlparse, hashlib, re, optparse, datetime, optparse
from nessrest import ness6rest
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename


app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5002
APP_MAXSCANS = 20

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = BASE_DIR + '/tmp'
POLICY_FOLDER = BASE_DIR + '/etc'
this = sys.modules[__name__]
this.nessscan = None
this.scanner = {}
this.scans = {}

@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/nessus/')
def index():
    return jsonify({ "page": "index" })


def _loadconfig():
    conf_file = BASE_DIR+'/nessus.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        os.environ['NO_PROXY'] = this.scanner["server_host"]
    else:
        print("Error: config file '{}' not found".format(conf_file))
        return { "status": "error", "reason": "config file not found" }

    try:
        this.nessscan = ness6rest.Scanner(
            url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
            login=this.scanner['server_username'],
            password=this.scanner['server_password'],
            insecure=True)
        if this.nessscan.res['scanners'][0]['status'] == "on":
            return { "status": "success" }
        else:
            return { "status": "error", "reason": "connection error to Nessus instance (bad credz? not available ?)" }
    except:
        return { "status": "error", "reason": "connection error to Nessus instance (bad credz? not available ?)" }


@app.route('/engines/nessus/reloadconfig')
def reloadconfig():
	res = { "page": "reloadconfig" }
	_loadconfig()
	res.update({"config": this.scanner})
	return jsonify(res)


@app.route('/engines/nessus/_upload_policy', methods=['POST'])
def _upload_policy():
    res = {	"page": "_upload_policy"}

    #@TODO

    return jsonify(res)


@app.route('/engines/nessus/_get_scanlist')
def _get_scanlist():
    res = {	"page": "_get_scanlist"}

    this.nessscan.action(action="scans", method="GET")
    scan_list = [scan for scan in this.nessscan.res['scans']]

    res.update({ "status": "success", "details": {"scan_list": scan_list}})
    return jsonify(res)


@app.route('/engines/nessus/getfindings/<scan_id>')
def getfindings(scan_id):
    res = {	"page": "getfindings", "scan_id": scan_id}
    scan_id = str(scan_id)

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)


    # check the scan status
    scan_status(scan_id)
    if not this.scans[scan_id]['status'] in ['FINISHED', 'STOPPED']:
        res.update({ "status": "error", "reason": "scan_id '{}' not finished".format(scan_id)})
        return jsonify(res)

    nessscan_id = str(this.scans[scan_id]["nessscan_id"])
    this.nessscan.action(action="scans/"+nessscan_id, method="GET")
    block_summary = {}
    block_issues = []
    issue_id = 1

    block_summary.update({
        "scanner_srvhost": this.scanner['server_host'],
        "scanner_srvport": this.scanner['server_port'],
        "status": this.nessscan.res['info']['status'],
        "policy": this.nessscan.res['info']['policy'],
        "assets": this.nessscan.res['info']['targets'],
        "nessus_scan_id": this.nessscan.res['info']['folder_id'],
        "scanner_start": this.nessscan.res['info']['scanner_start'],
        "uuid": this.nessscan.res['info']['uuid'],
        "hostcount": this.nessscan.res['info']['hostcount'],
        "name": this.nessscan.res['info']['name'],
        "scan_type": this.nessscan.res['info']['scan_type'],
        "hosts": {}
    })
    if this.nessscan.res['info']['status'] != "running":
        block_summary.update({"scanner_end": this.nessscan.res['info']['scanner_end']})

    sum_hosts = []
    host_list = this.nessscan.res['hosts']
    # this.scans[scan_id]["assets"]
    for h in host_list:
        sum_hosts.append({
            "hostname": h['hostname'],
            "critical": h['critical'],
            "high": h['high'],
            "medium": h['medium'],
            "low": h['low'],
            "info": h['info'],
            "severity": h['severity']
        })

    # optimize that shit
    for a in this.scans[scan_id]["assets"]:
        if a not in [h['hostname'] for h in host_list]:
            sum_hosts.append({
                "hostname": a,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "severity": "info"
            })


    block_summary.update({"hosts": sum_hosts})

    vulnerabilities = this.nessscan.res['vulnerabilities']
    # do it host by host baby
    for h in host_list:
        for v in vulnerabilities:
            this.nessscan.action(action="scans/"+nessscan_id+'/hosts/'+str(h['host_id'])+'/plugins/'+str(v['plugin_id']), method="GET")
            hostvulns = this.nessscan.res

            #print "plugin attributes:", hostvulns['info']['plugindescription']['pluginattributes']
            for hv in hostvulns['outputs']:
                #convert severity numbers
                if hv['severity'] == 0: hv['severity'] = 'info'
                if hv['severity'] == 1: hv['severity'] = 'low'
                if hv['severity'] == 2: hv['severity'] = 'medium'
                if hv['severity'] == 3: hv['severity'] = 'high'
                if hv['severity'] == 4: hv['severity'] = 'high' #'critical'

                _port = list(hv['ports'].keys())
                _porttype = _port[0].split(" / ")[1]
                _portid = _port[0].split(" / ")[0]

                plugin_output=re.sub('\nDate:.*\n','\n', str(hv['plugin_output']))
                finding_hash = hashlib.sha1(plugin_output).hexdigest()[:6]
                finding_type = str(hostvulns['info']['plugindescription']['pluginattributes']['plugin_information']['plugin_family']).lower().replace(" ", "_")
                finding_title = str(hostvulns['info']['plugindescription']['pluginattributes']['synopsis']) + " (" + _porttype + "/" + _portid + ") - " + finding_hash

                metadata = {
                    "tags": [
                        "nessus",
                        hostvulns['info']['plugindescription']['pluginattributes']['plugin_information']['plugin_family'].lower(),
                        hostvulns['info']['plugindescription']['pluginattributes']['plugin_information']['plugin_type'],
                        "pluginid_"+str(hostvulns['info']['plugindescription']['pluginattributes']['plugin_information']['plugin_id']),
                    ],
                }

                # metadata links ('see_also')
                if 'see_also' in hostvulns['info']['plugindescription']['pluginattributes'].keys():
                    metadata.update({"links": hostvulns['info']['plugindescription']['pluginattributes']['see_also']})

                # metadata vuln_refs ('ref_information')
                if 'ref_information' in hostvulns['info']['plugindescription']['pluginattributes'].keys():
                    vuln_refs = {}  #{ "CWE": "180, 120"}
                    for ref in hostvulns['info']['plugindescription']['pluginattributes']['ref_information']['ref']:
                        vuln_refs.update({
                            ref["name"]: ', '.join(ref['values']['value'])
                        })
                    metadata.update({"vuln_refs": vuln_refs})

                # metadata risk ('risk_information' + 'vuln_information')
                risk = {}
                if 'risk_information' in hostvulns['info']['plugindescription']['pluginattributes'].keys():
                    risk.update(hostvulns['info']['plugindescription']['pluginattributes']['risk_information'])
                if 'vuln_information' in hostvulns['info']['plugindescription']['pluginattributes'].keys():
                    risk.update(hostvulns['info']['plugindescription']['pluginattributes']['vuln_information'])
                if risk != {}:
                    metadata.update({"risk": risk})

                block_issues.append({
                    "issue_id": issue_id,
                    "timestamp": block_summary['scanner_start'],
                    "target": {
                        "addr": [h['hostname']],
                        "port_type": _porttype,
                        "port_id": _portid
                    },
                    "severity": hv['severity'],
                    "confidence": "certain",
                    "description": str(hostvulns['info']['plugindescription']['pluginattributes']['description']) + "\n\nScanner output:\n\n" + str(hv['plugin_output']),
                    "type": finding_type,
                    "solution": hostvulns['info']['plugindescription']['pluginattributes']['solution'],
                    "title": finding_title,
                    "metadata": metadata,
                    "raw": {
                        "outputs": hv,
                        "plugin_description": hostvulns['info']['plugindescription']['pluginattributes']
                    }
                })

            issue_id += 1


    # Generate a generic finding if not finding has been found on assets
    for a in this.scans[scan_id]["assets"]:
        if a not in host_list:
            block_issues.append({
                "issue_id": issue_id,
                "timestamp": block_summary['scanner_start'],
                "target": {
                    "addr": [a]
                },
                "severity": "info",
                "confidence": "certain",
                "description": "The host '"+str(a)+"' seems to be not reachable from the scanner access point.",
                "type": "availability",
                "solution": "None.",
                "title": "Host '"+str(a)+"' seems to be down",
                "metadata": {
                    "tags": ["nessus", "availability"]
                },
                "raw": {
                    "outputs": "The host '"+str(a)+"' seems to be not reachable from the scanner access point."
                }
            })
            issue_id += 1

    #Store the findings in a file
    with open(BASE_DIR+"/results/nessus_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": this.scans[scan_id],
            "summary": block_summary,
            "issues": block_issues
        }, report_file, default=_json_serial)

    res.update({"status": "success",
        "summary": block_summary,
        "issues": block_issues
    })
    # remove the scan from the active scan list
    clean_scan(scan_id)

    return jsonify(res)


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """
    #print "obj:", obj
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")

@app.route('/engines/nessus/getreport/<scan_id>')
def getreport(scan_id):
    scan_id = str(scan_id)
    filepath = BASE_DIR+"/results/nessus_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_from_directory(BASE_DIR+"/results/", "nessus_"+scan_id+".json")


def allowed_file(filename):
    # here the checks (size, format, ...)
    return True


@app.route('/engines/nessus/_get_custom_policy', methods=['POST'])
def _get_custom_policy():
    res = {	"page": "_get_custom_policy"}
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        res.update({"status": "error", "reason": "No file uploaded"})
        return jsonify(res)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        res.update({"status": "error", "reason": "No file selected"})
        return jsonify(res)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) + '_' + str(int(time.time()))
        #print(filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # remainder: purge the custom policy file?
        res.update({"status": "success", "details": {"filename": filename}})
        return jsonify(res)
    res.update({"status": "error", "reason": "undefined"})
    return jsonify(res)


@app.route('/engines/nessus/_get_local_policy', methods=['GET'])
def _get_local_policy(policy = None):
    res = {	"page": "_get_local_policy"}
    if not policy and not request.args.get('policy'):
        res.update({"status": "error", "reason": "'policy' arg is missing"})
        return jsonify(res)
    if not policy:
        policy = request.args.get('policy')
    policy_filename = POLICY_FOLDER + '/' + policy

    if not os.path.exists(policy_filename):
        res.update({"status": "error", "reason": "policy file not found",
                "details": {"filename": policy_filename, "name": policy}})
    else:
        res.update({"status": "success", "details":
            {"filename": policy_filename , "name": policy}})
    return jsonify(res)


@app.route('/engines/nessus/startscan', methods=['POST'])
def start_scan():
	#@todo: validate parameters and options format
    res = {	"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
			"status": "error",
			"reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
		})
        return jsonify(res)

    status()
    if this.scanner['status'] != "READY":
        res.update({
			"status": "refused",
			"details" : {
				"reason": "scanner not ready",
                "status": this.scanner['status']
		}})
        return jsonify(res)

    scan = {}

    # Parse the args in POST
    post_args = json.loads(request.data)
    scan_id = str(post_args['scan_id'])
    allowed_assets = []
    for asset in post_args['assets']:
        if asset["datatype"] in this.scanner["allowed_asset_types"]:
            # extract the net location from urls
            if asset["datatype"] == 'url':
                asset["value"] = "{uri.netloc}".format(uri=urlparse(asset["value"]))
            allowed_assets.append(asset["value"].strip())

    assets = ",".join(allowed_assets)
    policy_name = post_args['options']['policy'].split(".nessus")[0]

    # Check the policy is already uploaded to the scanner
    # Todo
    #tmp_res = requests.post(url_for('_get_custom_policy'), data=request.data)

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

    this.nessscan.policy_set(name=policy_name)
    this.nessscan.action(action="policies/" + str(this.nessscan.policy_id), method="put")
    this.nessscan.scan_add(
        targets=assets,
        name="[TO] Nessus Scan - {} ({})".format(scan_id, int(time.time())),
        )
    nessus_scan_id = this.nessscan.res["scan"]["id"]

    this.nessscan.scan_run()

    this.scans.update({
        scan_id: {
            "scan_id": scan_id,
            "scan_name": this.nessscan.scan_name,
            "nessscan_id": nessus_scan_id,
            "nessscan_uuid": this.nessscan.res['scan_uuid'],
            "options": post_args['options'],
            "policy_name": policy_name,
            "assets": post_args['assets'],
            "status": "STARTED",
            "started_at": int(time.time() * 1000),
            "findings": {}
        }
    })

    res.update({"status": "accepted", "details": scan })
    return jsonify(res)


@app.route('/engines/nessus/stop/<scan_id>', methods=['GET'])
def stop_scan(scan_id):
    res = {	"page": "stopscan"}
    scan_id = str(scan_id)

    # todo: use this.scans and nessus_scan_id
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.nessscan.action(action="scans/"+str(this.scans[scan_id]["nessscan_id"])+"/stop", method="POST")

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
    res = {	"page": "stopscans"}

    for scan_id in this.scans.keys():
        clean_scan(scan_id)

    res.update({"status": "success", "details": {
        "timestamp": int(time.time()) }})
    return jsonify(res)


@app.route('/engines/nessus/clean', methods=['GET'])
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    return jsonify(res)


@app.route('/engines/nessus/clean/<scan_id>', methods=['GET'])
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    scan_id = str(scan_id)
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
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
        scan = ness6rest.Scanner(
            url="https://{}:{}".format(this.scanner['server_host'], this.scanner['server_port']),
            login=this.scanner['server_username'],
            password=this.scanner['server_password'],
            insecure=True)
        if scan.res['scanners'][0]['status'] == "on":
            this.scanner['status'] = "READY"
            res.update({'status': 'READY',
                       'details': {'server_host': this.scanner['server_host'],
                       'server_port': this.scanner['server_port'],
                       'server_username': this.scanner['server_username'],
                       'engine_version': scan.res['scanners'][0]['engine_version'],
                       'engine_build': scan.res['scanners'][0]['engine_build'],
                       'scan_count': scan.res['scanners'][0]['scan_count']
                }})
        else:
            this.scanner['status'] = "ERROR"
            res.update({'status': 'ERROR', 'reason': 'Nessus engine not available'})
    except:
        this.scanner['status'] = "ERROR"
        res.update({'status': 'ERROR', 'reason': 'Nessus engine not available'})
    return jsonify(res)


@app.route('/engines/nessus/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    res = {	"page": "scan_status"}
    scan_id = str(scan_id)

    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)})

    # @todo: directly access to the right entry

    try:
        this.nessscan.action(action="scans/"+str(this.scans[scan_id]["nessscan_id"]), method="GET")
        nessus_scan_status = this.nessscan.res['info']['status']

        if nessus_scan_status == 'running': this.scans[scan_id]['status'] = "SCANNING"
        elif nessus_scan_status == 'completed': this.scans[scan_id]['status'] = "FINISHED"
        elif nessus_scan_status == 'canceled': this.scans[scan_id]['status'] = "STOPPED"
        else: this.scans[scan_id]['status'] = nessus_scan_status.upper()

    except:
        this.scans[scan_id]['status'] = "ERROR"

    return jsonify({
        "status": this.scans[scan_id]['status'],
        "scan": this.scans[scan_id]})

@app.route('/engines/nessus/info')
def info():
	return jsonify({ "page": "info", "engine_config": this.scanner})


@app.route('/engines/nessus/genreport', methods=['GET'])
def genreport(scan_id = None, report_format = "html"):
    #REPORT_FORMATS = ['html', 'csv', 'nessus']  # 'db' format not supported
    res = {	"page": "genreport" }
    scan_id = str(scan_id)

    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)})

    this.nessscan.action(action="scans", method="GET")
    scan_status = None
    for scan in this.nessscan.res['scans']:
        if scan['id'] == int(scan_id):
            scan_status = "found"
    if not scan_status:
        res.update({"status": "error", "reason": "'scan_id={}' not found".format(scan_id)})
        return jsonify(res)

    post_data = {"format": report_format}
    if report_format == "html":
        post_data.update({"chapters": "vuln_by_host"})

    this.nessscan.action(action="scans/{}/export".format(scan_id),
        method="POST", extra=post_data)

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
def getrawreports(scan_id = None, report_format = "html"):
    REPORT_FORMATS = ['html', 'csv', 'nessus']  # 'db' format not supported
    res = {	"page": "getreport" }
    scan_id = str(scan_id)

    if not scan_id and not request.args.get("scan_id"):
        res.update({"status": "error", "reason": "'scan_id' arg is missing"})
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
        res.update({"status": "error", "reason": "'scan_id={}' not found".format(scan_id)})
        return jsonify(res)

    post_data = {"format": report_format}
    if report_format == "html":
        post_data.update({"chapters": "vuln_by_host"})
    this.nessscan.action(action="scans/{}/export".format(scan_id),
        method="POST", extra=post_data)

    report_fileid = str(this.nessscan.res['file'])
    report_token = str(this.nessscan.res['token'])

    this.nessscan.action(action="scans/{}/export/{}/status"
        .format(scan_id, report_fileid), method="GET")
    if hasattr(this.nessscan.res, "status") and not this.nessscan.res['status'] == "ready":
        res.update({"status": "error", "reason": "report not available"})
        return jsonify(res)

    tmp_filename = "nessus_{}_{}_{}.{}".format(scan_id, report_fileid, int(time.time()), report_format)
    with open(UPLOAD_FOLDER+'/'+tmp_filename, 'wb') as handle:
        report_url = "https://{}:{}/scans/exports/{}/download".format(this.scanner['server_host'], this.scanner['server_port'], report_token)
        response = requests.get(report_url, stream=True, verify=False)

        if not response.ok:
            res.update({"status": "error", "reason": "something got wrong in d/l"})
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
    return jsonify({"page": "undefined", "status": "error", "reason": "page not found"})


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    if not os.path.exists(BASE_DIR+"/reports"):
        os.makedirs(BASE_DIR+"/reports")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP, default=APP_DEBUG)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
