#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json, os, subprocess, sys, requests, urlparse, datetime
from flask import Flask, request, jsonify, redirect, url_for

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5003
APP_MAXSCANS = 10

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.proc = None
this.scanner = {}
this.scanurl = None
this.scans = {}

requests.packages.urllib3.disable_warnings()


@app.route('/')
def default():
    return redirect(url_for('test'))


@app.route('/engines/burp/')
def index():
    return jsonify({"page": "index"})


@app.route('/engines/burp/clean')
def clean():
    res = { "page": "clean" }
    this.scans = {}
    loadconfig()
    return jsonify(res)


@app.route('/engines/burp/clean/<scan_id>')
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})
    for scan in this.scans:
        if str(scan["scan_id"]) == str(scan_id):
            this.scans.remove(scan)
            res.update({"status": "removed"})
            return jsonify(res)
    res.update({"status": "not found"})
    return jsonify(res)


@app.route('/engines/burp/_get_issues')
def _get_issues():
    res = {"page": "_get_issues"}
    url = this.scanurl + '/burp/scanner/issues'
    if request.args.get('url_prefix'):
        url += '?urlPrefix=' + request.args.get('url_prefix')

    headers = {'content-type': 'application/json'}
    r = requests.get(url, headers=headers)
    res.update(json.loads(r.text))

    return jsonify(res)


@app.route('/engines/burp/_addto_sitemap')
def _addto_sitemap(base_url = None):
    res = {"page": "_addto_sitemap"}
    if request.args.get('base_url'):
        base_url = request.args.get('base_url')
    else:
        if not base_url:
            res.update({'status': 'error', 'reason': 'missing base_url parameter'})
            return jsonify(res)

    r = None
    try:
        r = requests.get(base_url, verify=False,
            proxies={'http': 'http://localhost:8080',
            'https': 'http://localhost:8080'})
    except requests.exceptions.RequestException as e:
        print(e)
        res.update({'status': 'error', 'reason': 'unable to access the local proxies on port TCP/8080'})
        return jsonify(res)

    if r.status_code != 200:
        res.update({'base url': base_url, 'status_code': r.status_code})
        res.update({'status': 'error', 'reason': 'base url not available'})

    return jsonify(res)


@app.route('/engines/burp/_get_sitemap')
def _get_sitemap():
    res = {"page": "_get_sitemap"}
    url = this.scanurl + '/burp/target/sitemap'
    if request.args.get('url_prefix'):
        url += '?urlPrefix=' + request.args.get('url_prefix')

    headers = {'content-type': 'application/json'}
    r = requests.get(url, headers=headers)
    res.update(json.loads(r.text))

    return jsonify(res)


@app.route('/engines/burp/_do_spider')
def _do_spider(base_url = None):
    # Note: The baseUrl should be in scope for the Spider to run
    res = {"page": "_do_spider"}
    url = this.scanurl + '/burp/spider'
    if not base_url:
        base_url = request.args.get('base_url')

    if not base_url:
        res.update({"status": "error", "reason": "'base_url' parameter not set"})
        return jsonify(res)

    payload = {"baseUrl": base_url}
    r = requests.post(url, data=payload)
    res.update({'url': r.url, 'status_code': r.status_code})
	#todo: manage errors (if status_code != 200)

    return jsonify(res)


@app.route('/engines/burp/_get_spiderstatus')
def _get_spiderstatus():
    res = {	"page": "_get_spiderstatus" }
    res.update({"status": "error", "reason": "not implemented yet"})
	#@Todo: get the current spider scan

    return jsonify(res)


@app.route('/engines/burp/_get_scope')
def _get_scope():
    res = {"page": "_get_scope"}
    url = this.scanurl + '/burp/target/scope'
    if not request.args.get('url'):
        res.update({"status": "error", "reason": "'url' parameter not set"})
        return jsonify(res)

    url += '?url=' + request.args.get('url')
    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.get(url, headers=headers)
    res.update(json.loads(r.text))

    return jsonify(res)


@app.route('/engines/burp/_addto_scope')
def _addto_scope(_url = None):
    res = {"page": "_addto_scope"}
    url = this.scanurl + '/burp/target/scope'
    if not (request.args.get('url') or _url):
        res.update({"status": "error", "reason": "'url' parameter not set"})
        return jsonify(res)
    if _url:
        url += '?url=' + str(_url)
    else:
        url += '?url=' + str(request.args.get('url'))

    r = requests.put(url)
    res.update({'url': r.url, 'status_code': r.status_code})
	#todo: manage errors (if status_code != 200)

    return jsonify(res)


@app.route('/engines/burp/_rm_scope')
def _rm_scope():
    res = {"page": "_rm_scope"}
    url = this.scanurl + '/burp/target/scope'
    if not request.args.get('url'):
        res.update({"status": "error", "reason": "'url' parameter not set"})
        return jsonify(res)
    else:
        url += '?url=' + request.args.get('url')

    r = requests.delete(url)
    res.update({'url': r.url, 'status_code': r.status_code})
	#todo: manage errors (if status_code != 200)

    return jsonify(res)


@app.route('/engines/burp/_scan_status')
def _scan_status():
    res = {"page": "_scan_status"}
    url = this.scanurl + '/burp/scanner/status'
    #@todo: catch 'ConnectionError' (wait for engine fully started) before sending request

    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.get(url, headers=headers)
    res.update(json.loads(r.text))

    return jsonify(res)


@app.route('/engines/burp/_addto_scanqueue')
def _addto_scanqueue(base_url = None):
    # Note: The baseUrl should be in scope for the Active Scanner to run
    res = {"page": "_addto_scanqueue"}
    url = this.scanurl + '/burp/scanner/scans/active'
    if not (request.args.get('base_url') or base_url):
        print "_addto_scanqueue(): 'base_url' parameter not set"
        res.update({"status": "error", "reason": "'base_url' parameter not set"})
        return jsonify(res)

    if request.args.get('base_url'):
        base_url = request.args.get('base_url')

    payload = {"baseUrl": base_url}
    url += '?baseUrl=' + base_url

    _addto_scope(base_url)  #@Todo check before... and check returncode
    headers = {'content-type': 'application/json', 'accept': '*/*'}

    r = requests.post(url, data=payload, headers=headers)
    res.update({'url': r.url, 'status_code': r.status_code})
    #todo: manage errors (if status_code != 200)

    return jsonify(res)


@app.route('/engines/burp/_del_fullscanqueue')
def _del_fullscanqueue():
    res = {"page": "_del_fullscanqueue"}
    url = this.scanurl + '/burp/scanner/scans/active'

    r = requests.delete(url)
    res.update({'url': r.url, 'status_code': r.status_code})
	#todo: manage errors (if status_code != 200)

    return jsonify(res)


@app.route('/engines/burp/_get_scanqueue')
def _get_scanqueue():
    res = {"page": "_get_scanqueue"}
    url = this.scanurl + '/burp/scanner/scans/queue'

    if request.args.get('base_url'):
        url += "?base_url={}".format(request.args.get('base_url'))
        # useless till it's not implemented ;)

    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.get(url, headers=headers)
    #todo: manage errors (if status_code != 200)

    res.update({'url': r.url, 'status_code': r.status_code})
    r = json.loads(r.text)
    #print(r['urls_queued'])
    res.update({'urls_queued': r['urls_queued']})
    return jsonify(res)


def loadconfig():
    conf_file = BASE_DIR+'/burp.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
    else:
        return {"status": "error", "reason": "config file not found"}

    this.scanner = json.load(json_data)

    # check if an instance is running, then kill and restart it
    if hasattr(this.proc, 'pid') and not this.proc.poll():
        print(" * Terminate PID {}".format(this.proc.pid))
        this.proc.terminate()

    # delete and create tmp project file
    if os.path.exists(BASE_DIR+'/'+this.scanner['project_file']):
        os.remove(BASE_DIR+'/'+this.scanner['project_file'])
        #f = open(BASE_DIR+'/'+this.scanner.project_file, 'w')

    if os.path.exists(BASE_DIR+'/'+this.scanner['path']):
        cmd = "java -jar {}".format(BASE_DIR+'/'+this.scanner['path'])
    else:
        return {"status": "error", "reason": "jar file not found"}

	# check launching options
    if this.scanner['java_opts']:
        cmd += this.scanner['java_opts']
    if this.scanner['server_port'] or this.scanner['server_host']: # mandatory options
        cmd += " --server.port={}".format(this.scanner['server_port'])
        this.scanurl = "http://{}:{}".format(this.scanner['server_host'], this.scanner['server_port'])
    else:
        return {"status": "error", "reason": "'server_port' and/or 'server_host' option is missing"}
    if this.scanner['project_file']: # file is created if not exists
        cmd += " --project-file={}".format(BASE_DIR+'/'+this.scanner['project_file'])
    if this.scanner['config_file']: # file is created if not exists
        cmd += " --config-file={}".format(this.scanner['config_file'])

    this.proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(" * Burp REST API engine succesfully started on http://{}:{}/"
          .format(this.scanner['server_host'], this.scanner['server_port']))

    return {"status": "READY"}

@app.route('/engines/burp/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}

    status = loadconfig()['status']
    res.update({
        "status": status,
        "config": this.scanner,
        "details" : {
            "pid": this.proc.pid}})#,
            # "args": this.proc.args}})
    return jsonify(res)

@app.route('/engines/burp/startscan', methods=['POST'])
def start(base_url = None, spider = False):
    res = {"page": "startscan"}
    scan = {}
    data = json.loads(request.data)

    if not 'assets' in data.keys() or not'scan_id' in data.keys() or not 'base_url' in data['options']:
		res.update({
			"status": "error",
			"reason": "arg error, something is missing (ex: 'assets', 'scan_id', 'options/base_url')"
		})
		return jsonify(res)

    scan["scan_id"] = data["scan_id"]

    if data["scan_id"] in this.scans.keys():
        res.update({ "status": "error", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    # Initialize the scan parameters
    if not 'ports' in data['options'].keys():
        scan["target_port"] = "443"
    else:
        scan["target_port"] = str(list(data['options']['ports'])[0]) # get the 1st in list

    scan["target_host"] = str(list(data['assets'])[0]) # get the 1st in list
    scan["base_url"] = str(data['options']['protocol']) + "://" +\
        scan["target_host"]+":"+scan["target_port"]+str(data['options']['base_url'])
    scan["started_at"] = datetime.datetime.now()

    # if not request.args.get('base_url'):
    #     res.update({"status": "error", "reason": "'base_url' parameter not set"})
    #     return jsonify(res)

    #base_url = request.args.get('base_url')

    # Send it to spider if gently asked
    if 'spider' in data['options'].keys() and data['options']['spider']:
        # Add the base_url to scope
        _addto_scope(scan["base_url"])
        print("[STARTSCAN] _addto_scope({})".format(scan["base_url"]))
        _do_spider(scan["base_url"])
        print("[STARTSCAN] _do_spider({})".format(scan["base_url"]))
        #/!\ oh wait ... spidering takes times ...!!!!!

    # Send a request to the proxy in order to add it to the current sitemap
    _addto_sitemap(scan["base_url"])

    # Send to active scan queue
    _addto_scanqueue(scan["base_url"])

    #@TODO: manage errors

    # Prepare data returned
    this.scans.update({scan["scan_id"]: scan})
    res.update({
        "status": "accepted",
        "scan": scan,
        "details" : {"base_url": scan["base_url"]}})

    return jsonify(res)

# Deletes the full scan queue map from memory
@app.route('/engines/burp/stopscans')
def stop():
    res = {	"page": "stopscans" }
    url = this.scanurl + '/burp/scanner/scans/active'
    #@todo: catch 'ConnectionError' (wait for engine fully started) before sending request

    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.delete(url, headers=headers)
    if r.status_code != 200:
        res.update({"status": "error", "reason": "undefined", "details": json.loads(r.text)})
    else:
        res.update({"status": "success", "details": "Scan queue successfully deleted"})
    return jsonify(res)

@app.route('/engines/burp/reset')
def reset():
    res = {	"page": "reset" }
    url = this.scanurl + '/burp/reset'
    #@todo: catch 'ConnectionError' (wait for engine fully started) before sending request

    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        res.update({"status": "error", "reason": "undefined", "details": json.loads(r.text)})

    return jsonify(res)

@app.route('/engines/burp/status')
def status():
    res = {	"page": "status" }
    if hasattr(this.proc, 'pid') and not this.proc.poll():
        res.update({
			"status": "READY", # the rest api is alive
			"details": {
				"pid" : this.proc.pid#,
				#"args": this.proc.args }
		}})
    else:
        res.update({ "status": "ERROR" })

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

    # TODO: check scan percentage
    # try:
    #     r = requests.get(url=this.scans[scan_id]["url"], verify=False)
    #     if r.status_code == 200 and json.loads(r.text)["status"] == "READY":
    #         this.scans[scan_id]["status"] = "FINISHED"
    #         this.scans[scan_id]["finished_at"] = datetime.datetime.now()
    #         return True
    # except:
    #     print("API connexion error")
    #     return False

    return False


@app.route('/engines/burp/status/<scan_id>')
def scan_status(scan_id):
    res = { "page": "scan_status" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # @todo: check id the scan is finished or not
    _is_scan_finished(scan_id)

    # return the scan parameters and the status
    res.update({"scan": this.scans[scan_id]})
    res.update({"status": this.scans[scan_id]["status"]})

    return jsonify(res)


@app.route('/engines/burp/info')
def info():
    res = {	"page": "info",	"engine_config": this.scanner}

    if hasattr(this.proc, 'pid') and not this.proc.poll():
        res.update({
            "status": "running",
            "details": {
                "pid" : this.proc.pid}})#,
                #"args": this.proc.args }})
    else:
        res.update({"status": "idle"})

    return jsonify(res)


@app.route('/engines/burp/genreport/<scan_id>')
def genreport(scan_id):
    res = {"page": "report", "scan_id": scan_id}

    if not _is_scan_finished(scan_id):
        res.update({ "status": "error", "reason": "scan '{}' not finished".format(scan_id)})
        return jsonify(res)

    scan = this.scans[scan_id]

    url = this.scanurl + '/burp/scanner/issues?urlPrefix=' + scan['base_url']
    headers = {'content-type': 'application/json', 'accept': 'application/json'}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        res.update({"status": "error", "reason": "undefined", "details": json.loads(r.text)})
    else:
        res.update({"status": "success", "details": "genreport error: issues not available"})

    print(json.loads(r.text))
    issues = _parse_report(results=json.loads(r.text)['issues'], asset_name=scan['target_host'], asset_port=scan['target_port'])


	#@Todo: generate report

    #@Todo: store report in file (archive)

    #@Todo: clean Burp state

    return jsonify(res)

'''
{
  "issues": [
    {
      "confidence": "string",
      "host": "string",
      "httpMessages": [
        {
          "comment": "string",
          "highlight": "string",
          "host": "string",
          "port": 0,
          "protocol": "string",
          "request": [
            "string"
          ],
          "response": [
            "string"
          ],
          "statusCode": 0,
          "url": {
            "authority": "string",
            "content": {},
            "defaultPort": 0,
            "file": "string",
            "host": "string",
            "path": "string",
            "port": 0,
            "protocol": "string",
            "query": "string",
            "ref": "string",
            "userInfo": "string"
          }
        }
      ],
      "issueBackground": "string",
      "issueDetail": "string",
      "issueName": "string",
      "issueType": 0,
      "port": 0,
      "protocol": "string",
      "remediationBackground": "string",
      "remediationDetail": "string",
      "severity": "string",
      "url": {
        "authority": "string",
        "content": {},
        "defaultPort": 0,
        "file": "string",
        "host": "string",
        "path": "string",
        "port": 0,
        "protocol": "string",
        "query": "string",
        "ref": "string",
        "userInfo": "string"
      }
    }
  ]
}
'''
def _parse_report(results, asset_name, asset_port):
    # Findings categories:

    issues = []
    ts = int(time.time() * 1000)

    for result in results:
        print result['confidence']
        result['severity'].replace('Informational', 'info')
        result['severity'].replace('Low', 'low')
        result['severity'].replace('Medium', 'medium')
        result['severity'].replace('High', 'high')

    return issues


@app.route('/engines/burp/test')
def test():
    #if not APP_DEBUG:
    #    return jsonify({"page": "test"})

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
    return jsonify({"page": "not found"})


if __name__ == '__main__':
    if os.getuid() != 0:
        print("Error: Start the engine using root privileges !")
        sys.exit(-1)
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    loadconfig()
    app.run(debug=APP_DEBUG, host=APP_HOST, port=APP_PORT)
