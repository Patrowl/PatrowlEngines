#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, requests, json, urlparse, datetime, time, subprocess, hashlib, threading, optparse
from flask import Flask, request, jsonify, redirect, url_for, send_file, send_from_directory

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5005
APP_MAXSCANS = 10

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.proc = None
this.scanner = {}   # Scanner info
this.scans = {}     # Active scan list
requests.packages.urllib3.disable_warnings()


@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/arachni/')
def index():
    return jsonify({ "page": "index" })


@app.route('/engines/arachni/clean')
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    return jsonify(res)


@app.route('/engines/arachni/clean/<scan_id>')
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    #scan_id = int(scan_id)
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


def _loadconfig():
    conf_file = BASE_DIR+'/arachni.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['auth'] = (this.scanner['username'], this.scanner['password'])
        this.scanner['status'] = 'unknown'
    else:
        print("Error: config file '{}' not found".format(conf_file))
        return { "status": "ERROR", "reason": "config file not found", "details": {
            "filename": conf_file
        }}

    # check if an instance is running, then kill and restart it
    if hasattr(this.proc, 'pid'):
        print(" * Terminate PID {}".format(this.proc.pid))
        this.proc.terminate()

    cmd = this.scanner['path'] + "/bin/arachni_rest_server " \
        + "--address " + this.scanner['listening_host'] \
        + " --port " + this.scanner['listening_port'] \
        + " --authentication-username " + this.scanner['username'] \
        + " --authentication-password " + this.scanner['password'] \
        + " --reroute-to-logfile " + BASE_DIR +"/logs"
    this.proc = subprocess.Popen(cmd, shell=True, stdout=open("/dev/null", "w"), stderr=None)

    print(" * Arachni REST API server successfully started on http://{}:{}/"
          .format(this.scanner['listening_host'], this.scanner['listening_port']))

    return {"status": "READY"}

@app.route('/engines/arachni/reloadconfig')
def reloadconfig():
    res = { "page": "reloadconfig" }
    res.update(_loadconfig())
    res.update({
        "config": this.scanner,
        "details" : {"pid": this.proc.pid}
        })
    return jsonify(res)


@app.route('/engines/arachni/info')
def info():
    res = { "page": "info" }

    #todo check archni_status

    url = str(this.scanner['api_url']) + "/scans"
    try:
        r = requests.get(url=url, verify=False, auth=this.scanner['auth'])
        if r.status_code == 200:
            res.update({
                "status": "READY",
                # "details": { "engine_config": this.scanner }
                "engine_config": this.scanner
            })
        else:
            res.update({ "status": "ERROR", "details": {
                "engine_config": this.scanner }})
    except:
        res.update({ "status": "ERROR", "details": "connexion error to the API {}".format(url)})

    return jsonify(res)

'''
    # Function 'status()'
    #   - display current status of the scanner: READY, ERROR
    #   - display the last 10 scans status: SCANNING, DONE, ERROR + scan_id + timestamp
'''
@app.route('/engines/arachni/status')
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
    #scan_id = int(scan_id)
    if not scan_id in this.scans.keys():
        print("scan_id {} not found".format(scan_id))
        return False

    if this.scans[scan_id]["status"] in ["FINISHED", "STOPPED"]:
        return True

    try:
        url = this.scanner['api_url'] + "/scans/" + str(this.scans[scan_id]['arachni_scan_id']) + "/summary"
        r = requests.get(url=url, verify=False, auth=this.scanner['auth'])
        #print json.loads(r.text)["status"]
        if r.status_code == 200 and json.loads(r.text)["status"] == "done" and json.loads(r.text)["busy"] == False:
            this.scans[scan_id]["status"] = "FINISHED"
            this.scans[scan_id]["finished_at"] = datetime.datetime.now()
            return True

    except:
        print("API connexion error")
        return False

    return False

'''
    # Function 'scan_status(scan_id=86a5f993-30c2-47b7-a401-c4ae7e2a1e57)'
    #   - call the API to check status
    #   - display current status of the scan: SCANNING, DONE, ERROR
'''
@app.route('/engines/arachni/status/<scan_id>')
def scan_status(scan_id):
    res = { "page": "scan_status" }

    #scan_id = int(scan_id)
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check id the scan is finished or not
    #_is_scan_finished(scan_id)
    resp = None
    try:
        url = this.scanner['api_url'] + "/scans/" + this.scans[scan_id]['arachni_scan_id'] + "/summary"
        r = requests.get(url=url, verify=False, auth=this.scanner['auth'])
        resp = json.loads(r.text)
        if r.status_code == 200:
            if resp["status"] == "done" and resp["busy"] == False:
                this.scans[scan_id]["status"] = "FINISHED"
                this.scans[scan_id]["finished_at"] = datetime.datetime.now()
            else:
                this.scans[scan_id]["status"] = str(resp["status"]).upper()
    except:
        #print("API connexion error")
        this.scans[scan_id]["status"] = "ERROR"
        res.update({ "status": "ERROR",	"reason": "API error" })

    # return the scan parameters and the status
    res.update({
        "scan": this.scans[scan_id],
        "stats": resp["statistics"],
        "status": this.scans[scan_id]["status"]
        })

    return jsonify(res)


@app.route('/engines/arachni/startscan', methods=['POST'])
def start():
    res = { "page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
			"status": "ERROR",
			"reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
		})
        return jsonify(res)

    scan = {}
    data = json.loads(request.data)

    if not 'assets' in data.keys() or not'scan_id' in data.keys():# or not 'base_url' in data['options'].keys():
        res.update({
			"status": "ERROR",
			"reason": "arg error, something is missing (ex: 'assets', 'scan_id')"#, 'options/base_url')"
		})
        return jsonify(res)

    # scan["scan_id"] = data["scan_id"]
    scan["scan_id"] = str(data['scan_id'])
    scan_id = str(data['scan_id'])

    if data["scan_id"] in this.scans.keys():
        res.update({ "status": "ERROR", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    # Initialize the scan parameters
    asset = data['assets'][0]
    if asset["datatype"] not in this.scanner["allowed_asset_types"]:
        return jsonify({
                "status": "refused",
                "details" : {
                    "reason": "datatype '{}' not supported for the asset {}.".format(asset["datatype"], asset["value"])
            }})

    scan["asset_url"] = list(data['assets'])[0]['value'] # only take the 1st
    scan["target_host"] = urlparse.urlparse(scan["asset_url"]).netloc
    scan["target_protocol"] = urlparse.urlparse(scan["asset_url"]).scheme

    if 'ports' in data['options'].keys():
        scan["target_port"] = str(list(data['options']['ports'])[0]) # get the 1st in list
    elif urlparse.urlparse(scan["asset_url"]).port:
        scan["target_port"] = urlparse.urlparse(scan["asset_url"]).port
    elif scan["target_protocol"] == 'http':
        scan["target_port"] = 80
    elif scan["target_protocol"] == 'https':
        scan["target_port"] = 443


    scan["started_at"] = datetime.datetime.now()
    scan["options"] = {}
    if 'http' in data['options'].keys(): scan["options"].update({"http": data['options']['http']})
    if 'browser_cluster' in data['options'].keys(): scan["options"].update({"browser_cluster": data['options']['browser_cluster']})
    if 'scope' in data['options'].keys(): scan["options"].update({"scope": data['options']['scope']})
    if 'checks' in data['options'].keys(): scan["options"].update({"checks": list(data['options']['checks'])})
    if 'audit' in data['options'].keys(): scan["options"].update({"audit": data['options']['audit']})
    if 'no_fingerprinting' in data['options'].keys(): scan["options"].update({"no_fingerprinting": data['options']['no_fingerprinting']})
    if 'input' in data['options'].keys(): scan["options"].update({"input": data['options']['input']})

    #print scan

    url = this.scanner['api_url'] + "/scans"
    post_data = {
        "url": scan["asset_url"]
    }
    post_data.update(scan["options"])

    # Start the scan
    r = None
    try:
        r = requests.post(url=url, data=json.dumps(post_data), verify=False, auth=this.scanner['auth'])
        if r.status_code == 200:
            res.update({ "status": "accepted"})
            scan["status"] = "SCANNING"
            scan["arachni_scan_id"] = json.loads(r.text)['id']
            res.update({ "details": r.text })
        else:
            res.update({ "status": "ERROR", "reason": "something wrong with the API invokation"})
            scan["status"] = "ERROR"
            scan["finished_at"] = datetime.datetime.now()
    except:
        res.update({ "status": "ERROR", "reason": "connexion error"})
        scan["status"] = "ERROR"
        scan["finished_at"] = datetime.datetime.now()

    # Prepare data returned
    this.scans.update({ scan["scan_id"]: scan})
    res.update({"scan": scan})

    return jsonify(res)

"""
by default, the scan is paused -> report won't be available either
genresults bydefaut stop/delete the scan in the arachni context

"""
@app.route('/engines/arachni/stop/<scan_id>')
def stop_scan(scan_id):
    res = { "page": "stop" }

    #scan_id = int(scan_id)
    if not scan_id in this.scans.keys():
        res.update({ "status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    resp = None
    try:
        url = this.scanner['api_url'] + "/scans/" + this.scans[scan_id]['arachni_scan_id'] + "/pause"
        #r = requests.delete(url=url, verify=False, auth=this.scanner['auth'])
        r = requests.put(url=url, verify=False, auth=this.scanner['auth'])
        if r.status_code == 200:
            this.scans[scan_id]["status"] = "STOPPED"
            this.scans[scan_id]["finished_at"] = datetime.datetime.now()
        else:
            this.scans[scan_id]["status"] = "ERROR"

        res.update({ "status": "success",	"details": "scan successfully stopped" })
    except:
        this.scans[scan_id]["status"] = "ERROR"
        res.update({ "status": "ERROR",	"reason": "API error" })


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

@app.route('/engines/arachni/getfindings/<scan_id>')
def getfindings(scan_id):
    #scan_id = int(scan_id)
    res = { "page": "getfindings" , "scan_id": scan_id}

    if not _is_scan_finished(scan_id):
        res.update({ "status": "ERROR", "reason": "scan '{}' not finished".format(scan_id)})
        return jsonify(res)

    scan = this.scans[scan_id]
    app_url = scan["asset_url"]
    host = scan['target_host']
    port = scan['target_port']
    protocol = scan['target_protocol']
    url = this.scanner['api_url'] + "/scans/" + str(scan['arachni_scan_id']) + "/report.json"
    #print url

    try:
        r = requests.get(url=url, verify=False, auth=this.scanner['auth'])
        if r.status_code != 200:
            res.update({ "status": "ERROR", "reason": "something wrong with the API invokation"})
            return jsonify(res)
    except:
        res.update({ "status": "ERROR", "reason": "something wrong with the API invokation"})
        return jsonify(res)

    scan_results = json.loads(r.text)
    issues, summary = _parse_report(results=scan_results, asset_name=app_url, asset_host=host, asset_port=port, asset_protocol=protocol)

    # Definitely delete the scan in the arachni context
    try:
        url = this.scanner['api_url'] + "/scans/" + this.scans[scan_id]['arachni_scan_id']
        r = requests.delete(url=url, verify=False, auth=this.scanner['auth'])
        if r.status_code == 200:
            this.scans[scan_id]["status"] = "FINISHED"
        else:
            this.scans[scan_id]["status"] = "ERROR"
    except:
        this.scans[scan_id]["status"] = "ERROR"


    # Store the findings in a file
    with open(BASE_DIR+"/results/arachni_"+str(scan_id)+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({ "issues": issues, "summary": summary, "status": "success" })
    return jsonify(res)

def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


def _parse_report(results, asset_name, asset_host, asset_port, asset_protocol):
    """Parse the results provided by the scan tool and format them"""
    issues = []
    summary = {}
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
    }

    ts = int(time.time() * 1000)   # timestamp

    # Sitemap
    sitemap = results["sitemap"]
    nb_urls = len(sitemap)
    sitemap_str = ""
    for url in sorted(sitemap.keys()):
        if sitemap[url] == 200: sitemap_str = "".join((sitemap_str,str(url)+"\n"))

    sitemap_hash = hashlib.sha1(str(sitemap_str)).hexdigest()[:6]

    nb_vulns['info'] += 1
    issues.append({
        "issue_id": len(issues)+1,
        "severity": "info", "confidence": "certain",
        "target": {
            "addr": [asset_name, asset_host],
            "port_id": asset_port,
            "port_type": 'tcp',
            "protocol": asset_protocol
            },
        "title": "Sitemap {} (#URL: {}, HASH: {})".format(results["options"]["url"], nb_urls, sitemap_hash),
        "description": "Sitemap: \n\n{}".format(sitemap_str),
        "solution": "n/a",
        "metadata": {
            "tags": ["sitemap"]
        },
        "type": "sitemap",
        "raw": sitemap,
        "timestamp": ts
    })

    # Loop for issues found by the scanner
    for issue in results["issues"]:
        # reword 'informational' -> 'info'
        if issue['severity'] == "informational": issue['severity'] = "info"
        nb_vulns[issue['severity']] += 1

        confidence = ""
        if issue['trusted']:
            confidence = "certain"
        else:
            confidence = "firm"

        issues.append({
            "issue_id": len(issues)+1,
            "severity": issue['severity'],
            "confidence": confidence,
            "target": {
                "addr": [asset_name, asset_host],
                "port_id": asset_port,
                "port_type": 'tcp',
                "protocol": asset_protocol
                },
            "title": "{} ({} {} [{}])".format(
                issue['name'],
                str(issue['vector']['method']).upper(),          # GET, POST, PUT, ..
                urlparse.urlparse(issue['vector']['url']).path, # /index.php
                issue['vector']['affected_input_name']),        # query
            "description": "{}\\n\\nRequest: {}\\n\\nResponse: {}".format(
                issue['description'],
                issue['request']['headers_string'],
                issue['response']['headers_string']
                ),
            "solution": issue['remedy_guidance'],
            "metadata": {
                "tags": issue['tags'],
                "vuln_refs": {
                    "CWE": ', '.join([str(issue['cwe'])])
                },
                "links": list(issue['references'].values())
            },
            "type": issue['check']['shortname'],
            "raw": issue,
            "timestamp": ts
        })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "delta_time": results["delta_time"],
        "engine_name": "arachni",
        "engine_version": results["version"]
    }

    return issues, summary


@app.route('/engines/arachni/getreport/<scan_id>')
def getreport(scan_id):
    filepath = BASE_DIR+"/results/arachni_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    # return send_file(filepath,
    #     mimetype='application/json',
    #     attachment_filename='arachni_'+str(scan_id)+".json",
    #     as_attachment=True)
    return send_from_directory(BASE_DIR+"/results/", "arachni_"+scan_id+".json")


@app.route('/engines/arachni/test')
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
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    if not os.path.exists(BASE_DIR+"/logs"):
        os.makedirs(BASE_DIR+"/logs")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP, default=APP_DEBUG)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
