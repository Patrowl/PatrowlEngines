#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, urllib, time, datetime, optparse, json
from flask import jsonify, url_for, redirect, send_from_directory
from PatrowlEngineExceptions import PatrowlEngineExceptions

DEFAULT_APP_HOST = "127.0.0.1"
DEFAULT_APP_PORT = 5000
DEFAULT_APP_DEBUG = False
DEFAULT_APP_MAXSCANS = 25

def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """
    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


class PatrowlEngine:
    def __init__(self, app, base_dir, name, max_scans=DEFAULT_APP_MAXSCANS):
        self.app = app
        self.base_dir = str(base_dir)
        self.name = name
        self.version = 0
        self.description = ""
        self.allowed_asset_types = []
        self.options = {}
        self.scans = {}
        self.max_scans = max_scans
        self.status = "INIT"


    def __str__(self):
        return "%s - %s" % (self.name, self.version)

    def __to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "status": self.status,
            "allowed_asset_types": self.allowed_asset_types,
            "max_scans": self.max_scans,
            "nb_scans": len(self.scans.keys()),
        }


    def run_app(self, app_debug = DEFAULT_APP_DEBUG, app_host = DEFAULT_APP_HOST, app_port = DEFAULT_APP_PORT):
        if not os.path.exists(self.base_dir+"/results"):
            os.makedirs(self.base_dir+"/results")

        self._loadconfig()
        parser = optparse.OptionParser()
        parser.add_option("-H", "--host", help="Hostname of the Patrowl Engine [default %s]" % DEFAULT_APP_HOST, default=app_host)
        parser.add_option("-P", "--port", help="Port for the Patrowl Engine [default %s]" % DEFAULT_APP_PORT, default=app_port)
        parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)
        options, _ = parser.parse_args()
        self.app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)


    def test(self):
        res = "<h2>Test Page (DEBUG):</h2>"
        for rule in self.app.url_map.iter_rules():
            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ','.join(rule.methods)
            url = url_for(rule.endpoint, **options)
            res += urllib.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))
        return res

    def info(self):
        self.getstatus()
        return jsonify({"page": "info", "engine_config": self.__to_dict()})


    def _loadconfig(self):
        conf_file = self.base_dir+'/'+self.name+'.json'
        if os.path.exists(conf_file):
            engine_config = json.load(open(conf_file))
            self.version = engine_config["version"]
            self.description = engine_config["description"]
            self.options = engine_config["options"]
            self.allowed_asset_types = engine_config["allowed_asset_types"]
            self.status = "READY"
        else:
            self.status = "ERROR"
            return { "status": "ERROR", "reason": "config file not found" }

    def reloadconfig(self):
        res = { "page": "reloadconfig" }
        self._loadconfig()
        res.update({"config": {
            "status": self.status
        }})
        return jsonify(res)

    def had_options(self, options):
        opts = []
        if isinstance(options, basestring): # is a string
            opts.append(options)
        elif isinstance(options, list):
            opts = options

        for o in opts:
            if o not in self.options or  self.options[o] == None: return False

        return True

    def clean(self):
        res = {"page": "clean"}
        self.scans.clear()
        self._loadconfig()
        res.update({"status": "SUCCESS"})
        return jsonify(res)


    def clean_scan(self, scan_id):
        res = {"page": "clean_scan"}
        res.update({"scan_id": scan_id})

        if not scan_id in self.scans.keys():
            raise PatrowlEngineExceptions(1002)
            res.update({ "status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})
            return jsonify(res)

        self.scans.pop(scan_id)
        #Todo: force terminating all threads
        res.update({"status": "removed"})
        return jsonify(res)


    def getstatus_scan(self, scan_id):
        if not scan_id in self.scans.keys():
            raise PatrowlEngineExceptions(1002)
            return jsonify({
                "status": "ERROR",
                "details": "scan_id '{}' not found".format(scan_id)})

        all_threads_finished = False
        for t in self.scans[scan_id]['threads']:
            if t.isAlive():
                self.scans[scan_id]['status'] = "SCANNING"
                all_threads_finished = False
                break
            else:
                all_threads_finished = True

        if all_threads_finished and len(self.scans[scan_id]['threads']) >=1:
            self.scans[scan_id]['status'] = "FINISHED"
            self.scans[scan_id]['finished_at'] = int(time.time() * 1000)

        return jsonify({"status": self.scans[scan_id]['status']})


    def getstatus(self):
        res = {"page": "status"}

        if len(self.scans) == self.max_scans:
            self.status = "BUSY"
        else:
            self.status = "READY"

        scans = []
        for scan_id in self.scans.keys():
            self.getstatus_scan(scan_id)
            scans.append({scan_id: {
                "status": self.scans[scan_id]['status'],
                "started_at": self.scans[scan_id]['started_at'],
                "assets": self.scans[scan_id]['assets']
            }})

        res.update({
            "nb_scans": len(self.scans),
            "status": self.status,
            "scans": scans})
        return jsonify(res)


    def stop_scan(self, scan_id):
        res = {"page": "stop"}

        if not scan_id in self.scans.keys():
            raise PatrowlEngineExceptions(1002)
            res.update({ "status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})
            return jsonify(res)

        self.getstatus_scan(scan_id)
        if self.scans[scan_id]['status'] not in ["STARTED", "SCANNING"]:
            res.update({ "status": "ERROR", "reason": "scan '{}' is not running (status={})".format(scan_id, self.scans[scan_id]['status'])})
            return jsonify(res)

        for t in self.scans[scan_id]['threads']:
            t._Thread__stop()
        self.scans[scan_id]['status'] = "STOPPED"
        self.scans[scan_id]['finished_at'] = int(time.time() * 1000)

        res.update({"status": "SUCCESS"})
        return jsonify(res)

    # Stop all scans
    def stop(self):
        res = {"page": "stopscans"}
        for scan_id in self.scans.keys():
            self.stop_scan(scan_id)
        res.update({"status": "SUCCESS"})
        return jsonify(res)


    def init_scan(self, params):
        res = {"page": "startscan", "status": "INIT"}

        # check the scanner is ready to start a new scan
        if len(self.scans) == self.max_scans:
            res.update({
                "status": "ERROR",
                "reason": "Scan refused: max concurrent active scans reached ({})".format(self.max_scans)
            })
            return res

        self.getstatus()
        if self.status != "READY":
            res.update({
                "status": "ERROR",
                "details" : {
                    "reason": "scanner not ready",
                    "status": self.status
            }})
            return res

        data = json.loads(params)
        if not 'assets' in data.keys():
            res.update({
                "status": "ERROR",
                "details" : {
                    "reason": "arg error, something is missing ('assets' ?)"
            }})
            return res

        # Sanitize args :
        scan_id = str(data['scan_id'])
        res.update({"details": {"scan_id": scan_id}})
        new_scan = PatrowlEngineScan(
            assets=data['assets'],
            options=data['options'],
            scan_id=scan_id
        )

        self.scans.update({scan_id: new_scan.__dict__})
        return res


    def _parse_results(self, scan_id):
        if not scan_id in self.scans.keys():
            raise PatrowlEngineExceptions(1002)
            return jsonify({
                "status": "ERROR",
                "details": "scan_id '{}' not found".format(scan_id)})

        issues = []
        summary = {}

        scan = self.scans[scan_id]
        nb_vulns = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
        }

        for issue in self.scans[scan_id]["findings"]:
            issues.append(issue._PatrowlEngineFinding__to_dict())
            nb_vulns[issue.severity]+=1

        summary = {
            "nb_issues": len(issues),
            "nb_info": nb_vulns["info"],
            "nb_low": nb_vulns["low"],
            "nb_medium": nb_vulns["medium"],
            "nb_high": nb_vulns["high"],
            "engine_name": self.name,
            "engine_version": self.version
        }

        return issues, summary


    def getfindings(self, scan_id):

        try:
            scan = self.scans[scan_id]
        except:
            raise PatrowlEngineExceptions(1002)

        res = { "page": "getfindings", "scan_id": scan_id }

        # check if the scan is finished
        self.getstatus_scan(scan_id)
        if scan['status'] != "FINISHED":
            raise PatrowlEngineExceptions(1003)
            res.update({ "status": "ERROR", "reason": "scan_id '{}' not finished (status={})".format(scan_id, scan['status'])})
            return jsonify(res)

        issues, summary =  self._parse_results(scan_id)

        #Store the findings in a file
        with open(self.base_dir+"/results/"+self.name+"_"+scan_id+".json", 'w') as report_file:
            json.dump({
                "scan": {
                    "scan_id": scan_id
                },
                "summary": summary,
                "issues": issues
            }, report_file, default=_json_serial)

        # remove the scan from the active scan list
        self.clean_scan(scan_id)

        res.update({ "scan": scan_id, "summary": summary, "issues": issues, "status": "success"})
        return jsonify(res)

    def getreport(self, scan_id):
        filepath = "{}/results/{}_{}.json".format(self.base_dir, self.name, scan_id)
        if not os.path.exists(filepath):
            raise PatrowlEngineExceptions(1001)
            return jsonify({ "status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})

        return send_from_directory(
            self.base_dir+"/results/",
            "{}_{}.json".format(self.name, scan_id))

    def page_not_found(self):
        return jsonify({"page": "not found"})

    def default(self):
        return redirect(url_for('index'))

    def index(self):
        return jsonify({ "page": "index" })


class PatrowlEngineFinding:
    def __init__(self, issue_id, type, title, description, solution, severity,
                 confidence, raw, target_addrs, target_proto="", meta_links=[], meta_tags=[],
                 meta_vuln_refs=[], meta_risk=[], timestamp = None):
        self.issue_id = issue_id
        self.type = type
        self.title = title
        self.description = description
        self.solution = solution
        self.severity = severity
        self.confidence = confidence
        self.raw = raw
        self.target_addrs = target_addrs
        self.target_proto = target_proto
        self.meta_links = meta_links
        self.meta_tags = meta_tags
        self.meta_vuln_refs = meta_vuln_refs
        self.meta_risk = meta_risk
        if timestamp:
            self.timestamp = timestamp
        else:
            self.timestamp = int(time.time() * 1000)

    def __to_dict(self):
        return {
            "issue_id": self.issue_id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "solution": self.solution,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": {
                "addr": self.target_addrs, #list
                "protocol": self.target_proto
                },
            "metadata": {
                "tags": self.meta_tags,
                "links": self.meta_links,
                "vuln_refs": self.meta_vuln_refs,
                "meta_risk": self.meta_risk
                },
            "raw": self.raw,
            "timestamp": self.timestamp
        }

class PatrowlEngineScan:
    def __init__(self, assets, options, scan_id):
        self.assets = assets
        self.options = options
        self.scan_id = scan_id
        self.threads = []
        self.status = "STARTED"
        self.started_at = int(time.time() * 1000)
        self.findings = []

    def __to_dict(self):
        return {
            "assets": self.assets,
            "options": self.options,
            "scan_id": self.scan_id,
            "status": self.status
        }

    def add_issue(self, issue):
        self.findings.append(issue)

    def had_options(self, options):
        opts = []
        if isinstance(options, basestring): # is a string
            opts.append(options)
        elif isinstance(options, list):
            opts = options

        for o in opts:
            if o not in self.options or  self.options[o] == None: return False

        return True
