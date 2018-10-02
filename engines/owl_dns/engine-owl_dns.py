#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, json, time, urllib, hashlib, threading, datetime, copy, dns.resolver, socket, optparse
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5006
APP_MAXSCANS = 25

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scans = {}
this.scan_lock = threading.RLock()


@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/owl_dns/')
def index():
    return jsonify({ "page": "index" })


def _loadconfig():
    conf_file = BASE_DIR+'/owl_dns.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
        sys.path.append(this.scanner['sublister_bin_path'])
        sys.path.append(this.scanner['pythonwhois_bin_path'])
        globals()['sublist3r'] = __import__('sublist3r')
        globals()['pythonwhois'] = __import__('pythonwhois')

    else:
        print "Error: config file '{}' not found".format(conf_file)
        return { "status": "error", "reason": "config file not found" }


@app.route('/engines/owl_dns/reloadconfig')
def reloadconfig():
    res = { "page": "reloadconfig" }
    _loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/owl_dns/startscan', methods=['POST'])
def start_scan():
    #@todo: validate parameters and options format
    res = { "page": "startscan" }

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

    data = json.loads(request.data)
    if not 'assets' in data.keys():
        res.update({
            "status": "refused",
            "details" : {
                "reason": "arg error, something is missing ('assets' ?)"
        }})
        return jsonify(res)

    # Sanitize args :
    scan_id = str(data['scan_id'])
    scan = {
        'assets':       data['assets'],
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'findings':     {}
    }

    #print "scan:", scan

    this.scans.update({scan_id: scan})

    if 'do_whois' in scan['options'].keys() and data['options']['do_whois']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_get_whois, args=(scan_id, asset["value"],))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    if 'do_advanced_whois' in scan['options'].keys() and data['options']['do_advanced_whois']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_get_whois, args=(scan_id, asset["value"],))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    # subdomains enumeration using search engines, VT and public PassiveDNS API
    if 'do_subdomain_enum' in scan['options'].keys() and data['options']['do_subdomain_enum']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_subdomain_enum, args=(scan_id, asset["value"],))
                th.start()
                this.scans[scan_id]['threads'].append(th)

                # th = threading.Thread(target=_subdomain_enum, args=(scan_id, asset["value"],))
                # this.scans[scan_id]['threads'].append(th)
                # th.daemon = False
                # th.start()
                # #th.do_run = False
                # th.join()

    if 'do_subdomains_resolve' in scan['options'].keys() and data['options']['do_subdomains_resolve']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_dns_resolve, args=(scan_id, asset["value"], True))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    if 'do_dns_resolve' in scan['options'].keys() and data['options']['do_dns_resolve']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_dns_resolve, args=(scan_id, asset["value"], False))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    if 'do_subdomain_bruteforce' in scan['options'].keys() and data['options']['do_subdomain_bruteforce']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(target=_subdomain_bruteforce, args=(scan_id, asset["value"],))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    if 'do_reverse_dns' in scan['options'].keys() and data['options']['do_reverse_dns']:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = threading.Thread(target=_reverse_dns, args=(scan_id, asset["value"]))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    res.update({
        "status": "accepted",
        "details" : {
            "scan_id": scan['scan_id']
    }})

    return jsonify(res)


def __is_ip_addr(host):
    res = False
    try:
        res = socket.gethostbyname(host) == host
    except:
        pass
    return res

def __is_domain(host):
    res = False
    try:
        if not __is_ip_addr(host):
            #print str(pythonwhois.net.get_whois_raw(host))
            res = not "No entries found" in str(pythonwhois.net.get_whois_raw(host))
    except:
        pass
    return res


def _dns_resolve(scan_id, asset, check_subdomains=False):
    res = {}

    res.update({asset: __dns_resolve_asset(asset)})

    #scan_lock = threading.RLock()
    with this.scan_lock:
        this.scans[scan_id]["findings"]["dns_resolve"] = res

    if check_subdomains:
        res_dom = {}
        subdomains = _subdomain_enum(scan_id, asset)
        #print "subdomains:", subdomains
        for a in subdomains.keys():
            for s in subdomains[a]:
                data = __dns_resolve_asset(s)
                if len(data) > 0:
                    res_dom.update({asset: {s: data}})

        with this.scan_lock:
            this.scans[scan_id]["findings"]["subdomains_resolve"] = res_dom

    return res


def __dns_resolve_asset(asset):
    sub_res = []
    try:
        for record_type in ["CNAME", "A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV"]:
            try:
                answers = dns.resolver.query(asset, record_type)
                sub_res.append({
                    "record_type": record_type,
                    "values": [str(rdata) for rdata in answers]
                })
            except dns.resolver.NoAnswer:
                #print "*** No answer ***"
                pass
    except dns.resolver.NXDOMAIN:
        #print "*** The name", t, "does not exist ***"
        pass
    return sub_res



def _reverse_dns(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_ip_addr(asset): return res

    try:
        answers = dns.resolver.query(dns.reversename.from_address(asset), "PTR")
        res.update({
            asset: [str(rdata) for rdata in answers]
        })
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass

    scan_lock = threading.RLock()
    with scan_lock:
        this.scans[scan_id]["findings"]["reverse_dns"] = res

    return res


def _get_whois(scan_id, asset):
    res = {}

    #for asset in this.scans[scan_id]['assets']:
    # check the asset is a valid domain name
    if not __is_domain(asset): return res

    raw = pythonwhois.net.get_whois_raw(str(asset))
    if "No match for " in raw[0]:
        res.update({
            asset: {"errors": raw[0]}
        })
    else:
        res.update({
            asset: pythonwhois.parse.parse_raw_whois(raw)
        })

    scan_lock = threading.RLock()
    with scan_lock:
        this.scans[scan_id]["findings"]["whois"] = res

    return res


def _subdomain_bruteforce(scan_id, asset):
    res = {}
    SUB_LIST = [
        "www", "www1", "www2", "www3", "m",
        "ftp", "ftp1", "ftp2", "ftp3", "sftp",
        "mail", "mail1", "mail2", "mail3", "webmail", "smtp", "mx", "email", "owa", "imap",
        "prod", "dev", "pro", "test", "demo", "demo1", "demo2", "beta", "pre-prod", "preprod",
        "intra", "intranet", "internal", "backup", "backups",
        "db", "data", "mysql", "oracle", "pg",
        "ldap", "ldap2", "open", "survey",
        "remote", "blog", "blogs", "server", "git", "sys", "svn",
        "ns", "ns1", "ns2", "dns", "dns1", "dns2",
        "vpn", "vpn2", "support", "web", "api", "cdn", "ssh", "admin", "adm",
        "int", "recette", "re7", "pp", "stag", "staging",
        "video", "videos", "mob", "mobile", "mobi", "ws", "ad", "doc", "docs",
        "store", "feeds", "rss", "files",
        "mantis", "nagios", "owa", "outlook", "zabbix"
    ]


    valid_sudoms = []
    for sub in SUB_LIST:
        subdom = ".".join((sub, asset))
        results = __dns_resolve_asset(subdom)
        #print subdom, ":", results

        if len(results) > 0:
            valid_sudoms.append(subdom)

    # add the subdomain in scan['findings']['subdomains_list'] if not exists
    # @todo: mutex on this.scans[scan_id]['findings']['subdomains_list']
    if 'subdomains_list' in this.scans[scan_id]['findings'].keys():
        if asset in this.scans[scan_id]['findings']['subdomains_list']:
            if not subdom in this.scans[scan_id]['findings']['subdomains_list'][asset]:
                this.scans[scan_id]['findings']['subdomains_list'][asset].extend(valid_sudoms)
        else:
            this.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms
    else:
        this.scans[scan_id]['findings']['subdomains_list'] = {}
        this.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms

    # @todo: add the subdomain resolve in scan['findings']['subdomains_resolve'] if not exists
    # @todo: mutex on this.scans[scan_id]['findings']['subdomains_resolve']


    #print this.scans[scan_id]['findings']['subdomains_list']
    return res


def _subdomain_enum(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_domain(asset):
        return res

    sub_res = sublist3r.main(
        asset, 1, None,
        ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)

    res.update({asset: sub_res})

    # scan_lock = threading.RLock()
    if 'subdomains_list' in this.scans[scan_id]['findings'].keys():
        if asset in this.scans[scan_id]['findings']['subdomains_list']:
            for subdom in sub_res:
                if not subdom in this.scans[scan_id]['findings']['subdomains_list'][asset]:
                    this.scans[scan_id]['findings']['subdomains_list'][asset].extend(sub_res)
        else:
            # with this.scan_lock:
            this.scans[scan_id]['findings']['subdomains_list'][asset] = sub_res
    else:
        # with this.scan_lock:
        this.scans[scan_id]['findings']['subdomains_list'] = {}
        this.scans[scan_id]['findings']['subdomains_list'][asset] = sub_res

    #time.sleep(2)
    return res


@app.route('/engines/owl_dns/stop/<scan_id>')
def stop_scan(scan_id):
    res = { "page": "stop" }

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    scan_status(scan_id)
    if this.scans[scan_id]['status'] != "SCANNING":
        res.update({ "status": "error", "reason": "scan '{}' is not running (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    for t in this.scans[scan_id]['threads']:
        t._Thread__stop()
    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    res.update({"status": "success"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/owl_dns/stopscans', methods=['GET'])
def stop():
    res = { "page": "stopscans" }
    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/owl_dns/clean')
def clean():
    res = { "page": "clean" }
    this.scans.clear()
    _loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/owl_dns/clean/<scan_id>')
def clean_scan(scan_id):
    res = { "page": "clean_scan" }
    res.update({"scan_id": scan_id})

    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/owl_dns/status/<scan_id>')
def scan_status(scan_id):
    if not scan_id in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)})

    all_threads_finished = True

    for t in this.scans[scan_id]['threads']:
        #print "status/thread:", t
        #print "status/thread.isAlive():", t.isAlive()
        if t.isAlive():
            this.scans[scan_id]['status'] = "SCANNING"
            all_threads_finished = False
            break
        else:
            this.scans[scan_id]['threads'].remove(t)
            #all_threads_finished = True

    #print "status/len(threads):", len(this.scans[scan_id]['threads'])
    #print "status/all_threads_finished:", all_threads_finished, ", ", len(this.scans[scan_id]['threads'])
    # if all_threads_finished and len(this.scans[scan_id]['threads']) >=1:
    if all_threads_finished and len(this.scans[scan_id]['threads']) == 0:
        this.scans[scan_id]['status'] = "FINISHED"
        this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    return jsonify({"status": this.scans[scan_id]['status']})


@app.route('/engines/owl_dns/status')
def status():
    res = {"page": "status"}

    if len(this.scans) == APP_MAXSCANS:
        this.scanner['status'] = "BUSY"
    else:
        this.scanner['status'] = "READY"

    scans = []
    for scan_id in this.scans.keys():
        scan_status(scan_id)
        scans.append({scan_id: {
            "status": this.scans[scan_id]['status'],
            "started_at": this.scans[scan_id]['started_at'],
            "assets": this.scans[scan_id]['assets']
        }})

    res.update({
        "nb_scans": len(this.scans),
        "status": this.scanner['status'],
        "scanner": this.scanner,
        "scans": scans})
    return jsonify(res)


@app.route('/engines/owl_dns/info')
def info():
    status()
    return jsonify({"page": "info",    "engine_config": this.scanner})


def _parse_results(scan_id):
    issues = []
    summary = {}

    scan = this.scans[scan_id]
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
    }
    ts = int(time.time() * 1000)

    #print scan['findings']

    # dns resolve
    if 'dns_resolve' in scan['findings'].keys():
        for asset in scan['findings']['dns_resolve'].keys():

            dns_resolve_str = ""
            for record in sorted(scan['findings']['dns_resolve'][asset]):
                entry = "Record type '{}': {}".format(
                    record['record_type'], ", ".join(record['values']))
                dns_resolve_str = "".join((dns_resolve_str, entry+"\n"))

            dns_resolve_hash = hashlib.sha1(dns_resolve_str).hexdigest()[:6]

            nb_vulns['info'] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                    },
                "title": "DNS Resolution entries for '{}' (HASH: {})".format(
                    asset, dns_resolve_hash),
                "description": "DNS Resolution entries for '{}':\n\n{}".format(asset, dns_resolve_str),
                "solution": "n/a",
                "metadata": {
                    "tags": ["domains", "dns", "resolution"]
                },
                "type": "dns_resolve",
                "raw": scan['findings']['dns_resolve'][asset],
                "timestamp": ts
            })

    # subdomain resolve
    if 'subdomains_resolve' in scan['findings'].keys():
        for asset in scan['findings']['subdomains_resolve'].keys():
            for subdom in scan['findings']['subdomains_resolve'][asset].keys():
                subdom_resolve_str = ""
                for record in sorted(scan['findings']['subdomains_resolve'][asset][subdom]):
                    entry = "Record type '{}': {}".format(
                        record['record_type'], ", ".join(record['values']))
                    subdom_resolve_str = "".join((subdom_resolve_str, entry+"\n"))

                subdom_resolve_hash = hashlib.sha1(subdom_resolve_str).hexdigest()[:6]

                nb_vulns['info'] += 1
                issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                        },
                    "title": "DNS Resolution entries for '{}' (HASH: {})".format(
                        subdom, subdom_resolve_hash),
                    "description": "DNS Resolution entries for '{}':\n\n{}".format(
                        subdom, subdom_resolve_str),
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domains", "dns", "resolution", "subdomains"]
                    },
                    "type": "subdomains_resolve",
                    "raw": scan['findings']['subdomains_resolve'][asset][subdom],
                    "timestamp": ts
                })


    # reverse dns
    if 'reverse_dns' in scan['findings'].keys():
        for asset in scan['findings']['reverse_dns'].keys():
            nb_vulns['info'] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                    },
                "title": "IP '{}' points to domain name '{}'".format(
                    asset, ", ".join(scan['findings']['reverse_dns'][asset])),
                "description": "IP '{}' points to domain name '{}'".format(
                    asset, ", ".join(scan['findings']['reverse_dns'][asset])),
                "solution": "n/a",
                "metadata": {
                    "tags": ["domains", "dns", "reverse", "lookup"]
                },
                "type": "reverse_dns",
                "raw": scan['findings']['reverse_dns'][asset],
                "timestamp": ts
            })

    # subdomain list

    # bad messages replied by Sublist3r
    bad_str = ["Go to http://PTRarchive.com for best",
               "Use http://PTRarchive.com, the engine",
               "Sublist3r recommends"]
    if 'subdomains_list' in scan['findings'].keys():
        for asset in scan['findings']['subdomains_list'].keys():
            subdomains_str = ""
            for subdomain in sorted(scan['findings']['subdomains_list'][asset]):
                if any(x in subdomain for x in bad_str):
                    continue
                s = subdomain.replace("From http://PTRarchive.com: ", "")
                subdomains_str = "".join((subdomains_str, s+"\n"))
                # subdomains_str = "".join((subdomains_str, s+"\n"))

            subdomains_hash = hashlib.sha1(subdomains_str).hexdigest()[:6]
            if len(scan['findings']['subdomains_list'][asset]) == 0:
                scan['findings']['subdomains_list'][asset] = []

            nb_vulns['info'] += 1
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                    },
                "title": "List of subdomains for '{}' ({} found, HASH: {})".format(
                    asset, len(scan['findings']['subdomains_list'][asset]), subdomains_hash),
                "description": "Subdomain list for '{}': \n\n{}".format(
                    asset, subdomains_str),
                "solution": "n/a",
                "metadata": {
                    "tags": ["domains", "subdomains"]
                },
                "type": "subdomains_enum",
                "raw": scan['findings']['subdomains_list'][asset],
                "timestamp": ts
            })

    # whois info for domain
    if 'whois' in scan['findings'].keys():
        for asset in scan['findings']['whois'].keys():
            nb_vulns['info'] += 1
            # check errors
            if "errors" in scan['findings']['whois'][asset].keys():
                issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                        },
                    "title": "[Whois] No match for '{}'".format(asset),
                    "description": "No Whois data available for domain '{}'. Note that Whois is available for registered domains only (not sub-domains): \n{}".format(asset, scan['findings']['whois'][asset]['errors']),
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domains", "whois"]
                    },
                    "type": "whois_domain_error",
                    "raw": scan['findings']['whois'][asset]['errors'],
                    "timestamp": ts
                })
            else:
                whois_hash = hashlib.sha1(str(scan['findings']['whois'])).hexdigest()[:6]
                issues.append({
                    "issue_id": len(issues)+1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                        },
                    "title": "Whois info for '{}' (HASH: {})".format(asset, whois_hash),
                    "description": "Whois Info (raw): \n\n{}".format(str(scan['findings']['whois'][asset]['raw'][0])),
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domains", "whois"]
                    },
                    "type": "whois_fullinfo",
                    "raw": scan['findings']['whois'][asset]['raw'][0],
                    "timestamp": ts
                })

        # advanced whois info
        if 'do_advanced_whois' in scan['options'].keys() and scan['options']['do_advanced_whois']:
            for asset in scan['findings']['whois'].keys():
                if "errors" in scan['findings']['whois'][asset].keys(): continue

                issue = {
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                        },
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domains", "whois"]
                    },
                    "timestamp": ts
                }

                # status
                nb_vulns['info'] += 1
                dom_status = copy.deepcopy(issue) ; dom_status.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_domain_status",
                    "title": "[Whois] '{}' domain has status '{}'".format(asset, scan['findings']['whois'][asset]['status'][0]),
                    "description": "[Whois] '{}' domain has status '{}'".format(asset, scan['findings']['whois'][asset]['status'][0]),
                    "raw": scan['findings']['whois'][asset]['status'][0]
                })
                issues.append(dom_status)

                # registrar
                nb_vulns['info'] += 1
                dom_registrar = copy.deepcopy(issue) ; dom_registrar.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_registrar",
                    "title": "[Whois] '{}' domain registrar is '{}'".format(
                        asset, scan['findings']['whois'][asset]['registrar'][0]),
                    "description": "[Whois] '{}' domain registrar is '{}'".format(
                        asset, scan['findings']['whois'][asset]['registrar'][0]),
                    "raw": scan['findings']['whois'][asset]['registrar']
                })
                issues.append(dom_registrar)

                # emails
                if 'emails' in scan['findings']['whois'][asset].keys() and scan['findings']['whois'][asset]['emails']:
                    nb_vulns['info'] += 1
                    dom_emails = copy.deepcopy(issue) ; dom_emails.update({
                        "issue_id": len(issues)+1,
                        "type": "whois_emails",
                        "title": "[Whois] '{}' domain contact emails are: '{}'".format(
                            asset, ", ".join(scan['findings']['whois'][asset]['emails'])),
                        "description": "[Whois] '{}' domain contact emails are: '{}'".format(
                            asset, ", ".join(scan['findings']['whois'][asset]['emails'])),
                        "raw": scan['findings']['whois'][asset]['emails']
                    })
                    issues.append(dom_emails)

                # nameservers
                nb_vulns['info'] += 1
                dom_nameservers = copy.deepcopy(issue) ; dom_nameservers.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_nameservers",
                    "title": "[Whois] '{}' domain nameservers are '{}'".format(
                        asset, ", ".join(scan['findings']['whois'][asset]['nameservers'])),
                    "description": "[Whois] '{}' domain nameservers are '{}'".format(
                        asset, ", ".join(scan['findings']['whois'][asset]['nameservers'])),
                    "raw": scan['findings']['whois'][asset]['nameservers']
                })
                issues.append(dom_nameservers)

                # updated_date
                nb_vulns['info'] += 1
                update_dates = [d.date().isoformat() for d in scan['findings']['whois'][asset]['updated_date']]
                dom_updated_dates = copy.deepcopy(issue) ; dom_updated_dates.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_update_dates",
                    "title": "[Whois] '{}' domain was lastly updated the '{}'".format(
                        asset, max(scan['findings']['whois'][asset]['updated_date']).date().isoformat()),
                    "description": "[Whois] '{}' domain was updated at the following dates: \n\n{}".format(
                        asset, ", ".join(update_dates)),
                    "raw": scan['findings']['whois'][asset]['updated_date']
                })
                issues.append(dom_updated_dates)

                # creation_date
                nb_vulns['info'] += 1
                create_dates = [d.date().isoformat() for d in scan['findings']['whois'][asset]['creation_date']]
                dom_created_dates = copy.deepcopy(issue) ; dom_created_dates.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_creation_dates",
                    "title": "[Whois] '{}' domain was lastly created the '{}'".format(
                        asset, max(scan['findings']['whois'][asset]['creation_date']).date().isoformat()),
                    "description": "[Whois] '{}' domain was created at the following dates: \n\n{}".format(
                        asset, ", ".join(create_dates)),
                    "raw": scan['findings']['whois'][asset]['creation_date']
                })
                issues.append(dom_created_dates)

                # contacts (admin, tech, registrant, billing)
                nb_vulns['info'] += 1
                dom_contacts = copy.deepcopy(issue) ; dom_contacts.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_contacts",
                    "title": "[Whois] '{}' domain contacts (HASH: {})".format(
                        asset,
                        hashlib.sha1(str(scan['findings']['whois'][asset]['contacts'])).hexdigest()[:6]),
                    "description": "[Whois] '{}' domain contacts: \n\n{}".format(
                        asset, scan['findings']['whois'][asset]['contacts']),
                    "raw": scan['findings']['whois'][asset]['contacts']
                })
                issues.append(dom_contacts)

                # expiry date
                nb_vulns['info'] += 1
                expiry_dates = [d.date().isoformat() for d in scan['findings']['whois'][asset]['expiration_date']]
                dom_expiration_date = copy.deepcopy(issue) ; dom_expiration_date.update({
                    "issue_id": len(issues)+1,
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is registred until '{}'".format(
                        asset, max(scan['findings']['whois'][asset]['expiration_date']).date().isoformat()),
                    "description": "[Whois] '{}' domain is registred until '{}'\n\nAll dates: {}".format(
                        asset,
                        max(scan['findings']['whois'][asset]['expiration_date']).date().isoformat(),
                        ", ".join(expiry_dates)),
                    "raw": scan['findings']['whois'][asset]['expiration_date']
                })
                issues.append(dom_expiration_date)

                #Raise alarms at 6 months (low), 3 months (medium), 2 weeks (high) or when expired (high)
                exp_date = max(scan['findings']['whois'][asset]['expiration_date'])
                six_month_later = datetime.datetime.now() + datetime.timedelta(days=365/2)
                three_month_later = datetime.datetime.now() + datetime.timedelta(days=90)
                two_weeks_later = datetime.datetime.now() + datetime.timedelta(days=15)

                if exp_date < datetime.datetime.now():
                    nb_vulns['high'] += 1
                    dom_expiration_date_passed = copy.deepcopy(issue) ; dom_expiration_date_passed.update({
                        "issue_id": len(issues)+1,
                        "severity": "high",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is expired since '{}'".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is expired since '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(expiry_dates)),
                        "raw": scan['findings']['whois'][asset]['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_passed)
                elif exp_date < two_weeks_later:
                    nb_vulns['high'] += 1
                    dom_expiration_date_2w = copy.deepcopy(issue) ; dom_expiration_date_2w.update({
                        "issue_id": len(issues)+1,
                        "severity": "high",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(expiry_dates)),
                        "raw": scan['findings']['whois'][asset]['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_2w)
                elif exp_date < three_month_later:
                    nb_vulns['medium'] += 1
                    dom_expiration_date_3m = copy.deepcopy(issue) ; dom_expiration_date_3m.update({
                        "issue_id": len(issues)+1,
                        "severity": "medium",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 3 months)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 3 months)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(expiry_dates)),
                        "raw": scan['findings']['whois'][asset]['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_3m)
                elif exp_date < six_month_later:
                    nb_vulns['low'] += 1
                    dom_expiration_date_6m = copy.deepcopy(issue) ; dom_expiration_date_6m.update({
                        "issue_id": len(issues)+1,
                        "severity": "low",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 6 months)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 6 months)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(expiry_dates)),
                        "raw": scan['findings']['whois'][asset]['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_6m)

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        #"delta_time": results["delta_time"],
        "engine_name": "owl_dns",
        "engine_version": this.scanner["version"]
    }

    return issues, summary


@app.route('/engines/owl_dns/getfindings/<scan_id>')
def getfindings(scan_id):
    res = { "page": "getfindings", "scan_id": scan_id }

    # check if the scan_id exists
    if not scan_id in this.scans.keys():
        res.update({ "status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    status()
    if this.scans[scan_id]['status'] != "FINISHED":
        res.update({ "status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    issues, summary =  _parse_results(scan_id)
    scan = {
        "scan_id": scan_id
    }

    #Store the findings in a file
    with open(BASE_DIR+"/results/owl_dns_"+scan_id+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({ "scan": scan_id, "summary": summary, "issues": issues, "status": "success"})
    return jsonify(res)


@app.route('/engines/owl_dns/getreport/<scan_id>')
def getreport(scan_id):
    filepath = BASE_DIR+"/results/owl_dns_"+scan_id+".json"

    if not os.path.exists(filepath):
        return jsonify({ "status": "error", "reason": "report file for scan_id '{}' not found".format(scan_id)})

    return send_from_directory(BASE_DIR+"/results/", "owl_dns_"+scan_id+".json")


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


@app.route('/engines/owl_dns/test')
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
        res += urllib.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    _loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
