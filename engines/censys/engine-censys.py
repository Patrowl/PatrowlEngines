#!/usr/bin/python3
# -*- coding: utf-8 -*-
import censys.certificates
import time, OpenSSL, json, os, sys, requests, Queue, threading, ssl, socket, hashlib, urlparse, signal, optparse
from datetime import datetime, timedelta, date
from flask import Flask, redirect, url_for, jsonify, request, send_from_directory


app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5010
APP_MAXSCANS = 8
MAX_QUERIES = 10000


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {} # config of the engine
this.scans = {} # var where we stock informations about scans
this.STOPPED = [] # var where we stock the scans stopped when stopping the scans
this.queries = [] # queries queue to censys api
this.certificates = [] # where we stock the instances of a connection to censys api
this.keys = [] # where we stock the keys used to connect to censys api
this.requestor = [] # wherer we stock the threads demon which query censys api

@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/censys/')
def index():
    return jsonify({"page": "index"})


def _loadconfig():
    conf_file = BASE_DIR+'/censys.json'

    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.keys = this.scanner["keys"]
        del this.scanner["keys"]
        id_resq = 0
        for key in this.keys:
            this.requestor.append( threading.Thread(target=_requestor_d, args=(id_resq,) ) )
            this.certificates.append( censys.certificates.CensysCertificates(key["uid"], key["secret"]) )
            id_resq += 1
        for resq in this.requestor:
            resq._Thread__stop()

        this.lock = threading.Lock()

        for resq in this.requestor:
            resq.start()
    else:
        return {"status": "error", "reason": "config file not found", "detail": {"filename" : conf_file}}


@app.route('/engines/censys/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}

    this.requestor = []
    _loadconfig()
    res.update({"config": this.scanner})

    return jsonify(res)


@app.route('/engines/censys/startscan', methods=["POST"])
def start_scan():
    res = {"page": "startscan"}

    if len(this.queries) == MAX_QUERIES:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached"
        })
        return jsonify(res)

    data = json.loads(request.data)
    if not 'assets' in data.keys() or not 'options' in data.keys() or not 'keyword' in data['options'].keys() or len(data['options']['keyword']) == 0:
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('options'.'keyword' ? 'assets' ?)"
        }})
        return jsonify(res)
    if str(data['scan_id']) in this.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' already launched".format(data['scan_id'])
        }})
        return jsonify(res)

    _put_queries({
        "search": data['options']['keyword'],
        "scan_id": str(data['scan_id'])
    })
    this.scans[str(data['scan_id'])] = {
        "keyword":{},
        "issues":[],
        "options": [],
        "up_cert": {},
        "known_CA": [],
        "revoked": {},
        "unreachable_host": [],
        "status": "SCANNING",
        "gather": {
            "certificate_expired": [],
            "certificate_expired_in_two_weeks": [],
            "fail_load_crl": [],
            "certificate_in_crl": [],
            "analized_certificate": [],
            "host_self_signed": [],
            "alt_name_on_not_trusted_host": [],
            "ca_not_trusted": {}
        },
        "summary": {
            "engine_name": this.scanner["name"],
            "nb_issues": 0,
            "engine_version": this.scanner["version"],
        "nb_info":0, "nb_high":0, "nb_medium":0, "nb_low":0
        },
        "totalLeft": 0
    }
    if 'options' in data.keys():
        this.scans[str(data['scan_id'])]['options'] = data['options']

    this.scans[str(data['scan_id'])]['assets'] = data['assets']

    for keyword in data['options']['keyword']:
        this.scans[str(data['scan_id'])]["keyword"][keyword]={"left": 0, "begin": False}
    res.update({
        "status": "accepted",
        "details" : {
            "scan_id": str(data['scan_id'])
    }})
    return jsonify(res)


def _put_queries(dic):
    this.queries.insert(0,dic)


def _remove_scan(query):
    return not query["scan_id"] in this.STOPPED


@app.route('/engines/censys/stop/<scan_id>')
def stop_scan(scan_id):
    scan_id = str(scan_id)
    res = {"page": "stop"}
    if not scan_id in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)
    scan_status(scan_id)
    if this.scans[scan_id]['status'] not in ["SCANNING"]:
        res.update({"status": "error", "reason": "scan '{}' is not running (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    this.STOPPED.append(scan_id)
    this.queries = filter(_remove_scan, this.queries)
    this.scans[scan_id]['status'] = 'STOPPED'
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    this.STOPPED.remove(scan_id)
    clean_scan(scan_id)
    return jsonify(res)


@app.route('/engines/censys/clean')
def clean():
    message_error = "Some scan are not STOPPED or finished can't clean them :"
    res = {"page": "clean"}
    clean_error = False
    for scan in this.scans.keys():
        if this.scans[scan]['status'] != 'FINISHED' and this.scans[scan]['status'] != 'STOPPED':
            clean_error = True
        else:
            clean_scan(scan)
    if clean_error:
        res.update({"status": "error", "reason": message_error})
    _loadconfig()
    return jsonify(res)


@app.route('/engines/censys/clean/<scan_id>')
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    scan_id = str(scan_id)
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if this.scans[scan_id]['status'] != 'FINISHED' and this.scans[scan_id]['status'] != 'STOPPED':
        res.update({"status": "error", "reason": "CAN'T CLEAN '{}' because not FINISHED or STOPPED".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)

    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/censys/getreport/<scan_id>')
def getreport(scan_id):
    scan_id = str(scan_id)
    filepath = BASE_DIR+"/results/censys_{}.json".format(scan_id)

    if not os.path.exists(filepath):
        return jsonify({"status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})
    return send_from_directory(BASE_DIR+"/results/", "censys_{}.json".format(scan_id))


@app.route('/engines/censys/status/<scan_id>')
def scan_status(scan_id):
    scan_id = str(scan_id)
    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)
        })

    finish = False
    if not this.scans[scan_id]['status'] == 'STOPPED':
        for keyword in this.scans[scan_id]["keyword"].keys():
            if this.scans[scan_id]["keyword"][keyword]['begin'] and this.scans[scan_id]["keyword"][keyword]['left'] == 0:
                finish = True
        if finish:
            this.scans[scan_id]['status'] = "FINISHED"
        else:
            this.scans[scan_id]['status'] = "SCANNING"

    return jsonify({"scan_id": scan_id, "status": this.scans[scan_id]['status'],"detail": "'{}' certificates to proceed".format(this.scans[scan_id]['totalLeft'])})


@app.route('/engines/censys/status')
def status():
    res = {"page": "status"}
    scans = []
    for scan_id in this.scans.keys():
        scan_status(scan_id)
        scans.append({
            "scan_id": scan_id,
            "status": this.scans[scan_id]['status'],
            "detail": "'{}' certificates to proceed".format(this.scans[scan_id]['totalLeft'])
        })
    if APP_MAXSCANS <= len(this.scans):
        res.update({"status":"BUSY"})
    else:
        res.update({"status":"READY"})
    res.update({
        "scanner": this.scanner,
        "scans": scans
    })
    return jsonify(res)


@app.route('/engines/censys/debug')
def debug():
    return jsonify(this.scans)


@app.route('/engines/censys/info')
def info():
    return jsonify({"page": "info", "engine_config": this.scanner})


@app.route('/engines/censys/getfindings/<scan_id>')
def getfindings(scan_id):
    scan_id = str(scan_id)
    res = {"page": "getfindings", "scan_id": scan_id}
    if not scan_id in this.scans.keys():
        res.update({"status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)
        })
        return jsonify(res)
    status()
    if this.scans[scan_id]['status'] != "FINISHED" and this.scans[scan_id]['status'] != "STOPPED":
        res.update({
            "status": "ERROR",
            "details": "'{}' not finished or STOPPED (status='{}')".format(scan_id,this.scans[scan_id]['status'])
        })
        return jsonify(res)

    scan = {
            "scan_id": scan_id,
            "keyword": this.scans[scan_id]["keyword"].keys(),
            "options": this.scans[scan_id]['options'],
            "status":this.scans[scan_id]['status'],
            "started_at":this.scans[scan_id]['started_at'],
            "finished_at":this.scans[scan_id]['finished_at']
        }
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")

    _create_issues(scan_id)


    with open(BASE_DIR+"/results/censys_"+scan_id+".json","w") as report_file:
        json.dump({"scan": scan,
                "summary":this.scans[scan_id]["summary"],
                "issues":this.scans[scan_id]["issues"]},
            report_file, default=_json_serial)

    res.update({
        "scan": scan,
        "summary":this.scans[scan_id]["summary"],
        "issues":this.scans[scan_id]["issues"],
        "status": "success"
    })
    clean_scan(scan_id)
    return jsonify(res)


def _create_issues(scan_id):

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["certificate_expired"]) > 0:
        this.scans[scan_id]["gather"]["certificate_expired"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["certificate_expired"]:
            description = description + issues["description"] + "\n"
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Certificate is expired",
                                                      "solution" : "Renew certificate",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "certificate_expired",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "high",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","expired"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                    })
                this.scans[scan_id]["summary"]["nb_high"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Several certificates are expired",
                                                      "solution" : "Renew certificates",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "certificate_expired",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "high",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","expired"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                    })
            this.scans[scan_id]["summary"]["nb_high"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["certificate_expired_in_two_weeks"]) > 0:
        this.scans[scan_id]["gather"]["certificate_expired_in_two_weeks"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["certificate_expired_in_two_weeks"]:
            description += issues["description"]
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Certificates expire in two weeks",
                                                      "solution" : "Change certificate before two weeks",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "certificate_expired_in_two_weeks",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "high",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","expire"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                     })
                this.scans[scan_id]["summary"]["nb_info"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Several certificates expire in two weeks",
                                                  "solution" : "Change certificate before two weeks",
                                                  "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                  "type": "certificate_expired_in_two_weeks",
                                                  "target": {"addr": this.scans[scan_id]["assets"]},
                                                  "severity": "high",
                                                  "confidence": "certain",
                                                  "metadata": {"tags": ["certificate","expire"], "links": links},
                                                  "description": description,
                                                  "hash": hashlib.sha256(description).hexdigest()
                                                 })
            this.scans[scan_id]["summary"]["nb_high"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["fail_load_crl"]) > 0:
        this.scans[scan_id]["gather"]["fail_load_crl"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["fail_load_crl"]:
            description += issues["description"]
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Unable to load/reach revokation list",
                                                      "solution" : "N/A",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "fail_load_crl",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "info",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","revokation"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                      })
                this.scans[scan_id]["summary"]["nb_info"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Unable to load/reach revokation lists",
                                                  "solution" : "N/A",
                                                  "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                  "type": "fail_load_crl",
                                                  "target": {"addr": this.scans[scan_id]["assets"]},
                                                  "severity": "info",
                                                  "confidence": "certain",
                                                  "metadata": {"tags": ["certificate","revokation"], "links": links},
                                                  "description": description,
                                                  "hash": hashlib.sha256(description).hexdigest()
                                                  })
            this.scans[scan_id]["summary"]["nb_info"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["certificate_in_crl"]) > 0:
        this.scans[scan_id]["gather"]["certificate_in_crl"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["certificate_in_crl"]:
            description += issues["description"]
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Certificate is revoked",
                                                      "solution" : "Change the certificate",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "certificate_in_crl",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "high",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","revoked"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                      })
                this.scans[scan_id]["summary"]["nb_high"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Several certificates are revoked",
                                                  "solution" : "Change the certificate",
                                                  "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                  "type": "certificate_in_crl",
                                                  "target": {"addr": this.scans[scan_id]["assets"]},
                                                  "severity": "high",
                                                  "confidence": "certain",
                                                  "metadata": {"tags": ["certificate","revoked"], "links": links},
                                                  "description": description,
                                                  "hash": hashlib.sha256(description).hexdigest()
                                                  })
            this.scans[scan_id]["summary"]["nb_high"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["host_self_signed"]) > 0:
        this.scans[scan_id]["gather"]["host_self_signed"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["host_self_signed"]:
            description += issues["description"]
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Self-signed certificates",
                                                        "solution" : "Consider signing the certificate using a trusted CA",
                                                        "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                        "type": "host_self_signed",
                                                        "target": {"addr": this.scans[scan_id]["assets"]},
                                                        "severity": "medium",
                                                        "confidence": "certain",
                                                        "metadata": {"tags": ["certificate","self-signed"], "links": links},
                                                        "description": description,
                                                        "hash": hashlib.sha256(description).hexdigest()
                                                    })
                this.scans[scan_id]["summary"]["nb_medium"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Self-signed certificates",
                                                    "solution" : "Consider signing the certificates using a trusted CA",
                                                    "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                    "type": "host_self_signed",
                                                    "target": {"addr": this.scans[scan_id]["assets"]},
                                                    "severity": "medium",
                                                    "confidence": "certain",
                                                    "metadata": {"tags": ["certificate","self-signed"], "links": links},
                                                    "description": description,
                                                    "hash": hashlib.sha256(description).hexdigest()
                                                })
            this.scans[scan_id]["summary"]["nb_medium"]+=1

    description = ""
    links = []

    if len(this.scans[scan_id]["gather"]["analized_certificate"]) > 0:
        this.scans[scan_id]["gather"]["analized_certificate"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["analized_certificate"]:
            description += issues["description"]
            links.append(issues["links"])

        this.scans[scan_id]["summary"]["nb_issues"]+=1
        this.scans[scan_id]['issues'].append({"title": "List of analized certificate",
                                              "solution" : "n/a",
                                              "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                              "type": "ananlized_certificate",
                                              "target": {"addr": this.scans[scan_id]["assets"]},
                                              "severity": "info",
                                              "confidence": "certain",
                                              "metadata": {"tags": ["certificate","analized"], "links": links},
                                              "description": description,
                                              "hash": hashlib.sha256(description).hexdigest()
                                              })
        this.scans[scan_id]["summary"]["nb_info"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["alt_name_on_not_trusted_host"]) > 0:
        this.scans[scan_id]["gather"]["alt_name_on_not_trusted_host"].sort(lambda x,y : cmp(x['description'], y['description']))
        for issues in this.scans[scan_id]["gather"]["alt_name_on_not_trusted_host"]:
            description += issues["description"]
            target.append(issues["target"])
            links.append(issues["links"])

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Certificate CN or alternative names not trusted",
                                                      "solution" : "Verify if the CN or alternative names are trusted",
                                                      "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                      "type": "alt_name_on_not_trusted_host",
                                                      "target": {"addr": this.scans[scan_id]["assets"]},
                                                      "severity": "medium",
                                                      "confidence": "certain",
                                                      "metadata": {"tags": ["certificate","alt-name","trust"], "links": links},
                                                      "description": description,
                                                      "hash": hashlib.sha256(description).hexdigest()
                                                      })
                this.scans[scan_id]["summary"]["nb_medium"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Certificate CN or alternative names not trusted",
                                                  "solution" : "Verify if the CN or alternative names are trusted",
                                                  "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                  "type": "alt_name_on_not_trusted_host",
                                                  "target": {"addr": this.scans[scan_id]["assets"]},
                                                  "severity": "medium",
                                                  "confidence": "certain",
                                                  "metadata": {"tags": ["certificate","alt-name","trust"], "links": links },
                                                  "description": description,
                                                  "hash": hashlib.sha256(description).hexdigest()
                                                  })
            this.scans[scan_id]["summary"]["nb_medium"]+=1

    description = ""
    target = []
    links = []

    if len(this.scans[scan_id]["gather"]["ca_not_trusted"]) > 0:
        for issues in this.scans[scan_id]["gather"]["ca_not_trusted"].keys():
            target.append(this.scans[scan_id]["gather"]["ca_not_trusted"][issues]["target"])
            description += this.scans[scan_id]["gather"]["ca_not_trusted"][issues]["description"]
            links.append(this.scans[scan_id]["gather"]["ca_not_trusted"][issues]["links"])

            for ch in this.scans[scan_id]["gather"]["ca_not_trusted"][issues]["chains"]:
                description += "Certificate with chain : "

                for c in ch:
                    description = description + " - " + c["serial"] + " : " + c["subject"] + "\n"

            if "options" in this.scans[scan_id] and "verbose" in this.scans[scan_id]['options'] and this.scans[scan_id]['options']['verbose']:
                this.scans[scan_id]["summary"]["nb_issues"]+=1
                this.scans[scan_id]['issues'].append({"title": "Certificate signed by an unknown CA",
                                                        "solution" : "Check if the certificate should be trusted (add the CA in the trusted list ?)",
                                                        "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                        "type": "ca_not_trusted",
                                                        "target": {"addr": this.scans[scan_id]["assets"]},
                                                        "severity": "medium",
                                                        "confidence": "certain",
                                                        "metadata": {"tags": ["certificate","certification authority","trust"], "links": links},
                                                        "description": description,
                                                        "hash": hashlib.sha256(description).hexdigest()
                                                    })
                this.scans[scan_id]["summary"]["nb_high"]+=1
                description = ""
                links = []

        if not "options" in this.scans[scan_id] or not "verbose" in this.scans[scan_id]['options'] or not this.scans[scan_id]['options']['verbose']:
            this.scans[scan_id]["summary"]["nb_issues"]+=1
            this.scans[scan_id]['issues'].append({"title": "Certificates signed by an unknown CA",
                                                    "solution" : "Check if the certificate should be trusted (add the CA in the trusted list ?)",
                                                    "issue_id": this.scans[scan_id]["summary"]["nb_issues"],
                                                    "type": "ca_not_trusted",
                                                    "target": {"addr": this.scans[scan_id]["assets"]},
                                                    "severity": "medium",
                                                    "confidence": "certain",
                                                    "metadata": {"tags": ["certificate","certification authority","trust"], "links": links},
                                                    "description": description,
                                                    "hash": hashlib.sha256(description).hexdigest()
                                                })
            this.scans[scan_id]["summary"]["nb_high"]+=1


def _json_serial(obj):
    if isinstance(obj, datetime) or isinstance(obj,date):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serialzable ({})".format(obj))


def _requestor_d(key):
    while True:
        if len(this.queries) != 0:
            action = this.queries.pop()
            try:
                if "search" in action.keys():
                    if not action['scan_id'] in this.STOPPED:
                        this.scans[action['scan_id']]['started_at'] = int(time.time() * 1000)
                        for keyword in action['search']:
                            _search_cert(keyword,action['scan_id'], key)
                            time.sleep(2.5)
                if "view" in action.keys():
                    if not action['scan_id'] in this.STOPPED:
                        views = _get_view_cert(action['view'], key)
                        ignore = False
                        if "options" in this.scans[action['scan_id']] and "ignore_changed_certificate" in this.scans[action['scan_id']]['options'] and this.scans[action['scan_id']]['options']['ignore_changed_certificate']:
                            ignore = _ignore_changed_certificate(views, action['scan_id'])

                        if not ignore:
                            this.scans[action['scan_id']]["gather"]["ananlized_certificate"].append({
                                "links": "https://censys.io/certificates/{}".format(action['view']),
                                "description": "Ananlized certificate '{}'\n\n".format(views["parsed"]["subject_dn"])
                            })

                        if "options" in this.scans[action['scan_id']] and "do_scan_valid" in this.scans[action['scan_id']]['options'] and this.scans[action['scan_id']]['options']['do_scan_valid'] and not ignore:
                            _view_valid(views,action['view'],action['scan_id'],action['keyword'])

                        if "options" in this.scans[action['scan_id']] and "do_scan_trusted" in this.scans[action['scan_id']]['options'] and this.scans[action['scan_id']]['options']['do_scan_trusted'] and not ignore:
                            _view_trusted(views,action['scan_id'],action['keyword'])

                        if "options" in this.scans[action['scan_id']] and "do_scan_self_signed" in this.scans[action['scan_id']]['options'] and this.scans[action['scan_id']]['options']['do_scan_self_signed'] and not ignore:
                            _is_self_signed(views,action['scan_id'],action['keyword'])

                        if "options" in this.scans[action['scan_id']] and "do_scan_ca_trusted" in this.scans[action['scan_id']]['options'] and this.scans[action['scan_id']]['options']['do_scan_ca_trusted'] and not ignore:
                            _ca_trusted(views,action['scan_id'],action['keyword'],key,chain=[])
                        time.sleep(2.5)

                    with this.lock:
                        this.scans[action['scan_id']]["keyword"][action['keyword']]['left']-=1
                        this.scans[action['scan_id']]['totalLeft']-=1
                    if this.scans[action['scan_id']]['totalLeft'] == 0:
                        this.scans[action['scan_id']]['finished_at'] = int(time.time() * 1000)
            except Exception:
                print(sys.exc_info())
        else:
            time.sleep(1)


def _search_cert(keyword,scan_id, key):
    while True:
        # While Rate Limit Exceeded we wait and try again
        try:
            cert = this.certificates[key].search(keyword)
            #time.sleep(1)
            break
        except censys.base.CensysRateLimitExceededException:
            time.sleep(1)
        except censys.base.CensysNotFoundException:
            return False
        except Exception:
            time.sleep(1)
            print(sys.exc_info())

    # for all certificates
    try:
        for c in cert:
            if this.scans[scan_id]['totalLeft'] == MAX_QUERIES:
                break;
            _put_queries({"view": c["parsed.fingerprint_sha256"],"scan_id":scan_id,"keyword": keyword})
            with this.lock:
                this.scans[scan_id]['keyword'][keyword]['left']+=1
                this.scans[scan_id]['totalLeft']+=1
        this.scans[scan_id]['keyword'][keyword]['begin']=True
    except Exception:
        pass
    return True


def _get_view_cert(cert_sha, key):
    while True:
    # While Rate Limit Exceeded we wait and try again
        try:
            views = this.certificates[key].view(cert_sha) # get the certificates by censys api
            break
        except censys.base.CensysRateLimitExceededException: # fail Rate limit wait
            time.sleep(1)
        except censys.base.CensysNotFoundException:
            return False
        except Exception:
            time.sleep(1)
            print(sys.exc_info())
    return views


def _ignore_changed_certificate(views, scan_id):
    if not "options" in this.scans[scan_id] or not "changed_certificate_port_test" in this.scans[scan_id]['options']:
        port = [443]
    else:
        port = this.scans[scan_id]['options']['changed_certificate_port_test']
    try:
        url = views["parsed"]["subject"]["common_name"][0]
        if url in this.scans[scan_id]['unreachable_host']:
            return False
        if not _still_exist(url, views["parsed"]["serial_number"],port, scan_id):
            return True
    except Exception:
        this.scans[scan_id]['unreachable_host'].append(url)
    return False


def _view_valid(views,cert_sha,scan_id,keyword):

    datetstart = datetime.strptime(views["parsed"]["validity"]["start"],"%Y-%m-%dT%H:%M:%SZ") #make datetime on validity start
    datetend = datetime.strptime(views["parsed"]["validity"]["end"],"%Y-%m-%dT%H:%M:%SZ") #make datetime on validity end
    two_weeks_later = datetime.now() + timedelta(days=15)
    try:
        if datetend < datetime.today() or datetstart > datetime.today(): # see if certificates is outdated
            if views["parsed"]["subject"]["common_name"][0] in this.scans[scan_id]['unreachable_host']:
                this.scans[scan_id]["gather"]["certificate_expired"].append({
                    "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                    "links": "https://censys.io/certificates/{}".format(cert_sha),
                    "description": "Unreachable certificate expired '{}', we were unable to reach the certificate at '{}'\nValid from '{}' to '{}'\n\n".format(views["parsed"]["subject_dn"], views["parsed"]["subject"]["common_name"][0],datetstart, datetend)
                })
            else:
                this.scans[scan_id]["gather"]["certificate_expired"].append({
                    "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                    "links": "https://censys.io/certificates/{}".format(cert_sha),
                    "description": "Certificate expired '{}', certificate on '{}:{}'\nValid from '{}' to '{}'\n\n".format(views["parsed"]["subject_dn"],views["parsed"]["subject"]["common_name"][0], this.scans[scan_id]['up_cert'][views["parsed"]["subject"]["common_name"][0]]['port'],datetstart, datetend)
                })
        else:
            if datetend < two_weeks_later: # see if certificates is outdated
                if views["parsed"]["subject"]["common_name"][0] in this.scans[scan_id]['unreachable_host']:
                    this.scans[scan_id]["gather"]["certificate_expired_in_two_weeks"].append({
                        "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                        "links": "https://censys.io/certificates/{}".format(cert_sha),
                        "description": "Unreachable certificate will expired in two weeks'{}' we were unable to reach the certificate at '{}'\nEnd date : '{}'\n\n".format(views["parsed"]["subject_dn"],views["parsed"]["subject"]["common_name"][0],datetend)
                    })
                else:
                    this.scans[scan_id]["gather"]["certificate_expired_in_two_weeks"].append({
                        "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                        "links": "https://censys.io/certificates/{}".format(cert_sha),
                        "description": "Certificate will expired in two weeks'{}', certificate on '{}:{}'\nEnd date : '{}'\n\n".format(views["parsed"]["subject_dn"],views["parsed"]["subject"]["common_name"][0], this.scans[scan_id]['up_cert'][views["parsed"]["subject"]["common_name"][0]]['port'],datetend)
                    })

        crl_description = ""
        crl_fail = False

        for crl in views["parsed"]["extensions"]["crl_distribution_points"]: # for all crl see if certificates is in it

            if not ( crl in this.scans[scan_id]["revoked"].keys()): # new crl point we had it with his list in a "revoke" dict for later search
                this.scans[scan_id]["revoked"][crl]=[] # create structure of revoke
                try:
                    html = requests.get(crl, timeout=2) # get the crl list on the crl point

                    try:
                        crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, html.content) # we create a crl_object to help us

                        revoked_objects = crl_object.get_revoked() # we get the revoked cert

                        for rvk in revoked_objects: # for all revoked certificates we add it on our revoke dict
                            this.scans[scan_id]["revoked"][crl].append(rvk.get_serial()) # add it to the list
                    except OpenSSL.crypto.Error: # in case wrong format
                        try:
                            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, html.content)

                            revoked_objects = crl_object.get_revoked()

                            for rvk in revoked_objects:
                                this.scans[scan_id]["revoked"][crl].append(rvk.get_serial())

                        except OpenSSL.crypto.Error:
                            crl_fail = True
                            crl_description = crl_description + "Crl file '{}' unknow format\n".format(crl)
                    except TypeError: # in case crl list empty
                        crl_fail = True
                        crl_description = crl_description + "Crl file '{}' unknow format\n".format(crl)
                except Exception: # in case can't reach url of crl point
                    crl_fail = True
                    crl_description = crl_description + "Crl file '{}' unable to reach file\n".format(crl)

        if crl_fail:
            this.scans[scan_id]["gather"]["fail_load_crl"].append({
                "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                "links": "https://censys.io/certificates/{}".format(cert_sha),
                "description": crl_description + "\n"
            })

        if views["parsed"]["serial_number"] in this.scans[scan_id]["revoked"][crl]: # search our revoke dict if our certificates
            if views["parsed"]["subject"]["common_name"][0] in this.scans[scan_id]['unreachable_host']:
                this.scans[scan_id]["gather"]["certificate_in_crl"].append({
                    "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                    "links": "https://censys.io/certificates/{}".format(cert_sha),
                    "description": "Unreachable host in crl :\n" + crl_description + "\n"
                })
            else:
                this.scans[scan_id]["gather"]["certificate_in_crl"].append({
                    "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                    "links": "https://censys.io/certificates/{}".format(cert_sha),
                    "description": crl_description + "\n"
                })

    except KeyError:
        pass
    return True


def _still_exist(url, serial, port, scan_id):

    if url in this.scans[scan_id]['up_cert'].keys():
        return this.scans[scan_id]['up_cert'][url]['serial'] == serial

    for p in port:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            wrap_socket = ssl.wrap_socket(sock)

            wrap_socket.connect((url, p))

            cert = wrap_socket.getpeercert(True)
            try:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            except OpenSSL.crypto.Error: # in case wrong format
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            new_serial = cert.get_serial_number()
            this.scans[scan_id]['up_cert'][url] = {'serial': new_serial, 'port': p}

            break;
        except Exception:
            pass
            #print(sys.exc_info())
    return new_serial == int(serial)


def _view_trusted(views,scan_id,keyword):
    description = ""

    try:
        for sb in views["parsed"]["names"]:
            if not sb in this.scans[scan_id]['assets'] or (not "extended_trusted_host" in this.scans[scan_id]['options'] and not sb in this.scans[scan_id]['options']['extended_trusted_host']):
                description += sb+"\n"

        if description != "":
            this.scans[scan_id]["gather"]["alt_name_on_not_trusted_host"].append({
                "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                "links": "https://censys.io/certificates/{}".format(views["parsed"]["fingerprint_sha256"]),
                "description": "Certificate with altenative name on not trusted host '{}'\n Altenative name : '{}'\n\n".format(views["parsed"]["subject_dn"],description)
            })
    except KeyError:
        pass


def _is_self_signed(views,scan_id,keyword):
    if "self-signed" in views["tags"] and (not "trusted_ca_certificate" in this.scans[scan_id]["options"].keys() or not views["parsed"]["serial_number"] in this.scans[scan_id]["options"]["trusted_self_signed"]):
        if views["parsed"]["subject"]["common_name"][0] in this.scans[scan_id]['unreachable_host']:
            this.scans[scan_id]["gather"]["host_self_signed"].append({
                "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                "links": "https://censys.io/certificates/{}".format(views["parsed"]["fingerprint_sha256"]),
                "description": "Unreachable certificate is self-signed '{}', we were unable to reach the certificate at '{}'\n\n".format(views["parsed"]["subject_dn"],views["parsed"]["subject"]["common_name"][0])
            })
        else:
            this.scans[scan_id]["gather"]["host_self_signed"].append({
                "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                "links": "https://censys.io/certificates/{}".format(views["parsed"]["fingerprint_sha256"]),
                "description": "Certificate is self-signed '{}', certificate on '{}:{}\n\n".format(views["parsed"]["subject_dn"],views["parsed"]["subject"]["common_name"][0], this.scans[scan_id]['up_cert'][views["parsed"]["subject"]["common_name"][0]]['port'])
            })
        return True
    else:
        return False


def _ca_trusted(views,scan_id,keyword,key,chain=[]):
    chain.append({"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"]})
    if "self-signed" in views["tags"] or "root" in views["tags"] or ((not "basic_constaintd" in views["parsed"]["extensions"] or not "is_ca" in views["parsed"]["extensions"]["basic_constraints"] or views["parsed"]["extensions"]["basic_constraints"]["is_ca"] == True) and "trusted" in views["tags"]):
        if not "trusted_ca_certificate" in this.scans[scan_id]["options"].keys() or not views["parsed"]["serial_number"] in this.scans[scan_id]["options"]["trusted_ca_certificate"]:
            if not views["parsed"]["serial_number"] in this.scans[scan_id]["known_CA"]:
                this.scans[scan_id]["known_CA"].append(views["parsed"]["serial_number"])
                this.scans[scan_id]["gather"]["ca_not_trusted"][views["parsed"]["serial_number"]] = {
                    "target": {"serial": views["parsed"]["serial_number"], "subject": views["parsed"]["subject_dn"], "keyword":keyword},
                    "links": "https://censys.io/certificates/{}".format(views["parsed"]["fingerprint_sha256"]),
                    "description": "Certificate signed by an unknown CA '{}'\n\n".format(views["parsed"]["subject_dn"]),
                    "chains": [chain]
                }
                return True
            else:
                this.scans[scan_id]["gather"]["ca_not_trusted"][views["parsed"]["serial_number"]]["chains"].append(chain)
    else:
        try:
            html = requests.get(views["parsed"]["extensions"]["authority_info_access"]["issuer_urls"][0], timeout=2)
            the_certificate = hashlib.sha256(html.content).hexdigest()

            crl_object = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, html.content)
        except Exception:
            if not "extensions" in views["parsed"].keys() or not "authority_key_id" in views["parsed"]["extensions"].keys():
                return False

            while True:
                try:
                    cert = this.certificates[key].search("parsed.extensions.subject_key_id:" + views["parsed"]["extensions"]["authority_key_id"])
                    time.sleep(2.5)
                    break
                except censys.base.CensysRateLimitExceededException:
                    time.sleep(1)
                except censys.base.CensysNotFoundException:
                    return False
                except Exception:
                    time.sleep(1)
                    print(sys.exc_info())
            i = 0
            for ct in cert:
                if i == 0:
                    the_certificate = ct["parsed.fingerprint_sha256"]
                    i+=1
                else:
                    return False

        while True:
            try:
                views2 = this.certificates[key].view(the_certificate)#c["parsed.fingerprint_sha256"]) # get the certificates by censys api
                #time.sleep(2)
                break
            except censys.base.CensysRateLimitExceededException: # fail Rate limit wait
                time.sleep(1)
            except censys.base.CensysNotFoundException:
                return False
            except :
                time.sleep(1)
                print(sys.exc_info())
        _ca_trusted(views2,scan_id,keyword,key,chain=chain)

    return False


@app.route('/engines/censys/test')
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

def _exit_thread(signum, frame):
    print("\nClean Thread then exit ...")
    for resq in this.requestor:
        resq._Thread__stop()
    sys.exit(1)

@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, _exit_thread)
    #context = ('../../certificat/engine-censys.crt','../../certificat/engine-censys.key')
    #app.run(debug=APP_DEBUG, host=APP_HOST, port=APP_PORT, threaded=True) #, ssl_context=context)

    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP, default=APP_DEBUG)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
