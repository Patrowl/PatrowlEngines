#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os, sys, json, time, urllib, hashlib, threading, datetime, copy, dns.resolver, socket, optparse, random, string
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
import validators
import whois
from ipwhois import IPWhois
from modules.dnstwist import dnstwist
from modules.dkimsignatures import dkimlist
from concurrent.futures import ThreadPoolExecutor
import re

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5006
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 3))
APP_TIMEOUT = 3600

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scans = {}
this.scan_lock = threading.RLock()

this.resolver = dns.resolver.Resolver()
this.resolver.lifetime = this.resolver.timeout = 5.0

this.pool = ThreadPoolExecutor(5)


def get_random_string(n=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/owl_dns/')
def index():
    return jsonify({"page": "index"})


def _loadconfig():
    conf_file = f'{BASE_DIR}/owl_dns.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
        sys.path.append(this.scanner['sublist3r_bin_path'])
        globals()['sublist3r'] = __import__('sublist3r')
        dnstwist(this.scanner['dnstwist_bin_path'])

    else:
        print("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}

    version_filename = f'{BASE_DIR}/VERSION'
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        this.scanner["version"] = version_file.read().rstrip('\n')
        version_file.close()


@app.route('/engines/owl_dns/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/owl_dns/startscan', methods=['POST'])
def start_scan():
    # @todo: validate parameters and options format
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS*2:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res), 503

    data = json.loads(request.data)
    if 'assets' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }
        })
        return jsonify(res), 503

    scan_id = str(data['scan_id'])

    # this.scans.update({scan_id: None})
    this.scans.update({scan_id: {
        'status': 'STARTED',
        'started_at': int(time.time() * 1000),
        'assets': data['assets'],
    }})

    # print(f"Scan job '{scan_id}' reserved !")

    status()
    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": this.scanner['status']
            }
        })
        this.scans.update({scan_id: {
            'status': "ERROR",
        }})
        this.scans.pop(scan_id, None)
        # print(f"Scan job '{scan_id}' out: Scanner not ready")
        return jsonify(res), 503

    # Sanitize args :
    scan = {
        'assets': data['assets'],
        'threads': [],
        'futures': [],
        'dnstwist': {},
        'options': data['options'],
        'scan_id': scan_id,
        'status': "STARTED",
        'started_at': int(time.time() * 1000),
        'findings': {}
    }

    this.scans.update({scan_id: scan})

    if 'do_whois' in scan['options'].keys() and data['options']['do_whois']:
        for asset in data["assets"]:
            if asset["datatype"] in ["domain", "ip"]:
                # th = threading.Thread(target=_get_whois, args=(scan_id, asset["value"],))
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_get_whois, scan_id, asset["value"])
                this.scans[scan_id]['futures'].append(th)

    if 'do_advanced_whois' in scan['options'].keys() and data['options']['do_advanced_whois']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                # th = threading.Thread(target=_get_whois, args=(scan_id, asset["value"],))
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_get_whois, scan_id, asset["value"])
                this.scans[scan_id]['futures'].append(th)

    # subdomains enumeration using search engines, VT and public PassiveDNS API
    if 'do_subdomain_enum' in scan['options'].keys() and data['options']['do_subdomain_enum']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                # th = threading.Thread(target=_subdomain_enum, args=(scan_id, asset["value"],))
                # th.daemon = True
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_subdomain_enum, scan_id, asset["value"])
                this.scans[scan_id]['futures'].append(th)

    if 'do_subdomains_resolve' in scan['options'].keys() and data['options']['do_subdomains_resolve']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                # th = threading.Thread(target=_dns_resolve, args=(scan_id, asset["value"], True))
                # th.daemon = True
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_dns_resolve, scan_id, asset["value"], True)
                this.scans[scan_id]['futures'].append(th)

    if 'do_dns_resolve' in scan['options'].keys() and data['options']['do_dns_resolve']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                # th = threading.Thread(target=_dns_resolve, args=(scan_id, asset["value"], False))
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_dns_resolve, scan_id, asset["value"], False)
                this.scans[scan_id]['futures'].append(th)

    if 'do_spf_check' in scan['options'].keys() and data['options']['do_spf_check']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":

                th = threading.Thread(target=_perform_spf_check, args=(scan_id, asset["value"]))
                th.start()
                this.scans[scan_id]['threads'].append(th)

    if 'do_subdomain_bruteforce' in scan['options'].keys() and data['options']['do_subdomain_bruteforce']:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                # th = threading.Thread(target=_subdomain_bruteforce, args=(scan_id, asset["value"],))
                # th.daemon = True
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_subdomain_bruteforce, scan_id, asset["value"])
                this.scans[scan_id]['futures'].append(th)

    if 'do_reverse_dns' in scan['options'].keys() and data['options']['do_reverse_dns']:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                # th = threading.Thread(target=_reverse_dns, args=(scan_id, asset["value"]))
                # th.start()
                # this.scans[scan_id]['threads'].append(th)
                th = this.pool.submit(_reverse_dns, scan_id, asset["value"])
                this.scans[scan_id]['futures'].append(th)

    if 'do_dnstwist_subdomain_search' in scan['options'].keys() and data['options']['do_dnstwist_subdomain_search']:
        # Check if extra TLD should be tested
        tld = False
        if 'dnstwist_check_tld' in scan['options'].keys() and data['options']['dnstwist_check_tld']:
            tld = this.scanner['dnstwist_common_tlds']
        check_ssdeep = False
        if 'dnstwist_check_ssdeep' in scan['options'].keys() and data['options']['dnstwist_check_ssdeep']:
            check_ssdeep = True
        check_geoip = False
        if 'dnstwist_check_geoip' in scan['options'].keys() and data['options']['dnstwist_check_geoip']:
            check_geoip = True
        check_mx = False
        if 'dnstwist_check_mx' in scan['options'].keys() and data['options']['dnstwist_check_mx']:
            check_mx = True
        check_whois = False
        if 'dnstwist_check_whois' in scan['options'].keys() and data['options']['dnstwist_check_whois']:
            check_whois = True
        check_banners = False
        if 'dnstwist_check_banners' in scan['options'].keys() and data['options']['dnstwist_check_banners']:
            check_banners = True
        timeout = APP_TIMEOUT
        if 'max_timeout' in scan['options'].keys() and data['options']['max_timeout']:
            timeout = data['options']['max_timeout']

        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = this.pool.submit(dnstwist.search_subdomains, scan_id, asset["value"], tld, check_ssdeep, check_geoip, check_mx, check_whois, check_banners, timeout)
                this.scans[scan_id]['dnstwist'][asset["value"]] = {}
                this.scans[scan_id]['futures'].append(th)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })
    # print(', '.join([a['value'] for a in data['assets']]))

    # print(f"Scan job '{scan_id}' started (threads) !")

    return jsonify(res)


def __is_ip_addr(host):
    res = False
    try:
        res = socket.gethostbyname(host) == host
    except Exception:
        pass
    return res


def __is_domain(host):
    res = False
    try:
        res = validators.domain(host) == True
    except Exception:
        pass
    return res

def _recursive_spf_lookups(spf_line):
    spf_lookups = 0
    for word in spf_line.split(" "):
        if "include:" in word:
            url = word.replace("include:","")
            spf_lookups += 1
            dns_resolve = __dns_resolve_asset(url,"TXT")
            for record in dns_resolve:
                for value in record["values"]:
                    if "spf" in value:
                        spf_lookups += _recursive_spf_lookups(value)
    return spf_lookups

def _do_dmarc_check(spf_dict,dns_records):
    for record in dns_records:
        for value in record["values"]:
            if "DMARC" in value:
                spf_dict.pop("no_dmarc_record")
                if "p=none" in value:
                    spf_dict["insecure_dmarc_policy"] = "high"
                if "sp=none" in value:
                    spf_dict["insecure_dmarc_subdomain_sp"] = "high"
                for word in value.split(" "):
                    if "pct=" in word:
                        num = int(re.sub('\D', '', word))
                        if num < 100:
                            spf_dict["dmarc_partial_coverage"] = "medium"

def _do_dkim_check(domain_name):
    for dkim in dkimlist:
        dkim_record = dkim + "._domainkey." + domain_name
        dns_records = __dns_resolve_asset(dkim_record,"TXT")
        print(dkim,dns_records)

def _perform_spf_check(scan_id,asset_value):
    _do_dkim_check(asset_value)
    dns_records = __dns_resolve_asset(asset_value,"TXT")
    dmarc_records = __dns_resolve_asset("_dmarc."+asset_value,"TXT")
    spf_dict = {"no_spf_found":"high",
                "no_dmarc_record": "high",
                "spf_lookups": 0
            }
    _do_dmarc_check(spf_dict,dns_records)
    _do_dmarc_check(spf_dict,dmarc_records)
    for record in dns_records:
        for value in record["values"]:
            if "spf" in value:
                spf_dict.pop("no_spf_found")
                spf_lookups = _recursive_spf_lookups(value)
                spf_dict["spf_lookups"] = spf_lookups
                if spf_lookups > 10:
                    spf_dict["spf_too_many_lookups"] = "medium"
                if "+all" in value:
                    spf_dict["+all_spf_found"] = "very high"
                elif "~all" in value:
                    spf_dict["~all_spf_found"] = "medium"
                elif "?all" in value:
                    spf_dict["no_spf_all_or_?all"] = "high"
                elif "all" not in value:
                    spf_dict["no_spf_all_or_?all"] = "high"

    with this.scan_lock:
        this.scans[scan_id]["findings"]["spf_dict"] = {asset_value:spf_dict}
    return spf_dict


def _dns_resolve(scan_id, asset, check_subdomains=False):
    res = {}

    res.update({asset: __dns_resolve_asset(asset)})

    with this.scan_lock:
        this.scans[scan_id]["findings"]["dns_resolve"] = res

    if check_subdomains:
        res_dom = {}
        subdomains = _subdomain_enum(scan_id, asset)
        for a in subdomains.keys():
            for s in subdomains[a]:
                data = __dns_resolve_asset(s)
                if len(data) > 0:
                    res_dom.update({asset: {s: data}})

        with this.scan_lock:
            if 'subdomains_resolve' not in this.scans[scan_id]['findings'].keys():
                this.scans[scan_id]['findings']['subdomains_resolve'] = {}
            this.scans[scan_id]["findings"]["subdomains_resolve"].update(res_dom)

    return res


def __dns_resolve_asset(asset,type_of_record=False):
    sub_res = []
    try:
        record_types = ["CNAME", "A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV"]
        if type_of_record:
            record_types = [type_of_record]
        for record_type in record_types:
            try:
                answers = this.resolver.query(asset, record_type)
                sub_res.append({
                    "record_type": record_type,
                    "values": [str(rdata) for rdata in answers]
                })
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.Timeout:
                pass
            except Exception:
                pass
    except dns.resolver.NXDOMAIN:
        pass
    return sub_res


def _reverse_dns(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_ip_addr(asset):
        return res

    try:
        answers = this.resolver.query(dns.reversename.from_address(asset), "PTR")
        res.update({
            asset: [str(rdata) for rdata in answers]
        })
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass

    scan_lock = threading.RLock()
    with scan_lock:
        if 'reverse_dns' not in this.scans[scan_id]['findings'].keys():
            this.scans[scan_id]['findings']['reverse_dns'] = {}
        this.scans[scan_id]["findings"]["reverse_dns"].update(res)

    return res


def _get_whois(scan_id, asset):
    res = {}

    # Check the asset is a valid domain name or IP Address
    if not __is_domain(asset) and not __is_ip_addr(asset):
        return res

    if __is_domain(asset):
        w = whois.whois(str(asset))
        if w.domain_name is None:
            res.update({
                asset: {"errors": w}
            })
        else:
            res.update({
                asset: {"raw": {'dict': w, 'text': w.text}, "text": w.text, "type": "domain"}
            })
    if __is_ip_addr(asset):
        w = IPWhois(str(asset).strip()).lookup_rdap()
        res.update({
            asset: {"raw": {'dict': w, 'text': "see raw"}, "text": "see raw", "type": "ip"}
        })

    scan_lock = threading.RLock()
    with scan_lock:
        if 'whois' not in this.scans[scan_id]['findings'].keys():
            this.scans[scan_id]['findings']['whois'] = {}
        this.scans[scan_id]['findings']['whois'].update(res)

    return res


def _subdomain_bruteforce(scan_id, asset):
    res = {}
    SUB_LIST = [
        "www", "www1", "www2", "www3", "m", "mob", "mobile",
        "ftp", "ftp1", "ftp2", "ftp3", "sftp",
        "mail", "mail1", "mail2", "mail3", "webmail", "smtp", "mx", "email", "owa", "imap",
        "prod", "dev", "pro", "test", "demo", "demo1", "demo2", "beta", "pre-prod", "preprod",
        "int", "acc",
        "intra", "intranet", "internal", "backup", "backups", "share",
        "db", "db1", "db2", "data", "mysql", "oracle", "pg",
        "ldap", "ldap2", "open", "survey",
        "remote", "blog", "blogs", "server", "git", "sys", "svn",
        "ns", "ns1", "ns2", "dns", "dns1", "dns2",
        "vpn", "vpn2", "support", "web", "api", "cdn", "ssh", "admin", "adm",
        "int", "rec", "recette", "re7", "pp", "stag", "staging",
        "video", "videos", "mob", "mobile", "mobi", "ws", "ad", "doc", "docs",
        "store", "feeds", "rss", "files",
        "mantis", "nagios", "outlook", "zabbix"
    ]

    # Check wildcard domain
    w_domain = "{}.{}".format(
        get_random_string(), asset
    )
    if len(__dns_resolve_asset(w_domain)) > 0:
        return res

    valid_sudoms = []
    for sub in SUB_LIST:
        subdom = ".".join((sub, asset))
        results = __dns_resolve_asset(subdom)

        if len(results) > 0:
            valid_sudoms.append(subdom)

    # add the subdomain in scan['findings']['subdomains_list'] if not exists
    # @todo: mutex on this.scans[scan_id]['findings']['subdomains_list']
    if 'subdomains_list' in this.scans[scan_id]['findings'].keys():
        if asset in this.scans[scan_id]['findings']['subdomains_list']:
            if subdom not in this.scans[scan_id]['findings']['subdomains_list'][asset]:
                this.scans[scan_id]['findings']['subdomains_list'][asset].extend(valid_sudoms)
                # this.scans[scan_id]['findings']['subdomains_list'][asset].update(valid_sudoms)
        else:
            this.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms
    else:
        this.scans[scan_id]['findings']['subdomains_list'] = {}
        this.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms

    # @todo: add the subdomain resolve in scan['findings']['subdomains_resolve'] if not exists
    # @todo: mutex on this.scans[scan_id]['findings']['subdomains_resolve']

    return res


def _subdomain_enum(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_domain(asset):
        return res

    sub_res = sublist3r.main(
        asset, 1, None,
        ports=None,
        silent=True,
        verbose=True,
        enable_bruteforce=False,
        engines=None)

    res.update({asset: sub_res})

    if 'subdomains_list' in this.scans[scan_id]['findings'].keys():
        if asset in this.scans[scan_id]['findings']['subdomains_list']:
            for subdom in sub_res:
                if subdom not in this.scans[scan_id]['findings']['subdomains_list'][asset]:
                    this.scans[scan_id]['findings']['subdomains_list'][asset].extend(sub_res)
        else:
            # with this.scan_lock:
            this.scans[scan_id]['findings']['subdomains_list'][asset] = list(sub_res)
    else:
        # with this.scan_lock:
        this.scans[scan_id]['findings']['subdomains_list'] = {}
        this.scans[scan_id]['findings']['subdomains_list'][asset] = list(sub_res)

    # time.sleep(2)
    return res


@app.route('/engines/owl_dns/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "stop"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    scan_status(scan_id)
    if this.scans[scan_id]['status'] != "SCANNING":
        res.update({"status": "error", "reason": "scan '{}' is not running (status={})".format(scan_id, this.scans[scan_id]['status'])})
        return jsonify(res)

    for t in this.scans[scan_id]['threads']:
        # t._Thread__stop()
        # t.terminate()
        try:
            t.join()
            this.scans[scan_id]['threads'].remove(t)
        except Exception:
            pass
    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)

    res.update({"status": "success"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/owl_dns/stopscans', methods=['GET'])
def stop():
    res = {"page": "stopscans"}
    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/owl_dns/clean')
def clean():
    res = {"page": "clean"}
    this.scans.clear()
    _loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/owl_dns/clean/<scan_id>')
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # Terminate thread if any
    for t in this.scans[scan_id]['threads']:
        try:
            # t._Thread__stop()
            # t.terminate()
            # print("{}: clean threads '{}'".format(scan_id, t))
            t.join()
            this.scans[scan_id]['threads'].remove(t)
        except Exception as e:
            print(e)
            pass
    #
    # for t in this.scans[scan_id]['futures']:
    #     try:
    #         # t._Thread__stop()
    #         # t.terminate()
    #         print("{}: clean futures '{}'".format(scan_id, t))
    #         print(dir(t))
    #         # t.join()
    #     except Exception as e:
    #         print(e)
    #         pass

    # Remove Scan for current scans
    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


@app.route('/engines/owl_dns/status/<scan_id>')
def scan_status(scan_id):
    if scan_id not in this.scans.keys():
        return jsonify({
            "status": "ERROR",
            "details": "scan_id '{}' not found".format(scan_id)
        })

    all_threads_finished = True

    if 'threads' in this.scans[scan_id]:
        for t in this.scans[scan_id]['threads']:
            # print("scan_status-thread:", t.name, t.native_id)
            if t.is_alive():
                this.scans[scan_id]['status'] = "SCANNING"
                all_threads_finished = False
                break
            else:
                # Terminate thread
                t.join()
                this.scans[scan_id]['threads'].remove(t)

    if 'futures' in this.scans[scan_id]:
        for f in this.scans[scan_id]['futures']:
            if not f.done():
                this.scans[scan_id]['status'] = "SCANNING"
                all_threads_finished = False
                break
            else:
                try:
                    dnstwist_asset, dnstwist_results = f.result()
                    this.scans[scan_id]['dnstwist'][dnstwist_asset] = dnstwist_results
                except Exception:
                    pass
                this.scans[scan_id]['futures'].remove(f)

    if 'threads' not in this.scans[scan_id] and 'futures' not in this.scans[scan_id]:
        this.scans[scan_id]['status'] = "STARTED"
        all_threads_finished = False

    try:
        if all_threads_finished and len(this.scans[scan_id]['threads']) == 0 and len(this.scans[scan_id]['futures']) == 0:
            this.scans[scan_id]['status'] = "FINISHED"
            this.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    except Exception:
        pass

    return jsonify({"status": this.scans[scan_id]['status']})


@app.route('/engines/owl_dns/status')
def status():
    res = {"page": "status"}

    if len(this.scans) == APP_MAXSCANS*2:
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

    # print("thread-count:", threading.active_count())
    # for thread in threading.enumerate():
    #     print("{}:{}".format(thread.name, thread.native_id))
    return jsonify(res)


@app.route('/engines/owl_dns/info')
def info():
    status()
    return jsonify({"page": "info", "engine_config": this.scanner})


def _parse_results(scan_id):
    issues = []
    summary = {}

    scan = this.scans[scan_id]
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    ts = int(time.time() * 1000)

    # dnstwist

    if 'dnstwist' in this.scans[scan_id].keys():
        for asset in this.scans[scan_id]['dnstwist'].keys():
            try:
                dnstwist_issues = dnstwist.parse_results(
                    ts, asset, this.scans[scan_id]['dnstwist'][asset])
            except KeyError:
                app.logger.error("dnstwist: missing result (domain-name)")
                dnstwist_issues = []
            for dnstwist_issue in dnstwist_issues:
                nb_vulns[dnstwist_issue['severity']] += 1
                issues.append(dnstwist_issue)

    # dns resolve
    if 'dns_resolve' in scan['findings'].keys():
        for asset in scan['findings']['dns_resolve'].keys():

            dns_resolve_str = ""
            for key, value in sorted(scan['findings']['dns_resolve'].items(), key=lambda x:x[1], reverse=True):
                for record in value:
                    entry = "Record type '{}': {}".format(
                            record['record_type'], ", ".join(record['values']))
                    dns_resolve_str = "".join((dns_resolve_str, entry+"\n"))

            dns_resolve_hash = hashlib.sha1(dns_resolve_str.encode("utf-8")).hexdigest()[:6]

            dns_records = scan['findings']['dns_resolve'][asset]
            nb_vulns['info'] += 1
            issues.append({
                "issue_id": len(issues) + 1,
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

    if 'spf_dict' in scan['findings'].keys():
        for asset in scan['findings']['spf_dict'].keys():
            spf_check = scan['findings']['spf_dict'][asset]
            # TODO find a good hash for this one
            spf_hash = hashlib.sha1("test".encode("utf-8")).hexdigest()[:6]
            issues.append({
                "issue_id": len(issues) + 1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                },
                "title": "SPF check for '{}' (HASH: {})".format(
                    asset, spf_hash),
                "description": "DNS Resolution entries for '{}':\n\n{}".format(asset, spf_hash),
                "solution": "n/a",
                "metadata": {
                    "tags": ["domains", "dns", "resolution"]
                },
                "type": "spf_check",
                "raw": scan['findings']['spf_dict'][asset],
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

                subdom_resolve_hash = hashlib.sha1(subdom_resolve_str.encode("utf-8")).hexdigest()[:6]

                nb_vulns['info'] += 1
                issues.append({
                    "issue_id": len(issues) + 1,
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
                "issue_id": len(issues) + 1,
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
    bad_str = [
        "Go to http://PTRarchive.com for best",
        "Use http://PTRarchive.com, the engine",
        "Sublist3r recommends",
        "API count exceeded",
        "Too Many Requests",
        "<", ">",
    ]
    if 'subdomains_list' in scan['findings'].keys():
        for asset in scan['findings']['subdomains_list'].keys():
            subdomains_str = ""
            subdomains_list = sorted(set(scan['findings']['subdomains_list'][asset]))
            subdomains_list_clean = []

            # Associate these findings to the asset or create new assets
            create_new_assets = False
            if 'subdomain_as_new_asset' in scan['options'].keys() and scan['options']['subdomain_as_new_asset']:
                create_new_assets = True

            for subdomain in subdomains_list:
                if any(x in subdomain for x in bad_str) or subdomain.replace(' ', '') == '':
                    continue
                s = subdomain.replace("From http://PTRarchive.com: ", "")
                subdomains_list_clean.append(s)
                subdomains_str = "".join((subdomains_str, s+"\n"))

                # New issue when a subdomain is found
                nb_vulns['info'] += 1
                if create_new_assets:
                    issues.append({
                        "issue_id": len(issues) + 1,
                        "severity": "info", "confidence": "certain",
                        "target": {
                            "addr": [s],
                            "protocol": "domain"
                        },
                        "title": "Subdomain found: {}".format(s),
                        "description": "Subdomain found:\n\n{}".format(s),
                        "solution": "n/a",
                        "metadata": {
                            "tags": ["domains", "subdomain"]
                        },
                        "type": "subdomain",
                        "raw": s,
                        "timestamp": ts
                    })
                else:
                    issues.append({
                        "issue_id": len(issues) + 1,
                        "severity": "info", "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "domain"
                        },
                        "title": "Subdomain found: {}".format(s),
                        "description": "Subdomain found:\n\n{}".format(s),
                        "solution": "n/a",
                        "metadata": {
                            "tags": ["domains", "subdomain"]
                        },
                        "type": "subdomain",
                        "raw": s,
                        "timestamp": ts
                    })

            # New issue when on the domain list
            subdomains_hash = hashlib.sha1(subdomains_str.encode("utf-8")).hexdigest()[:6]
            if len(subdomains_list_clean) == 0:
                subdomains_list_clean = []

            nb_vulns['info'] += 1
            issues.append({
                "issue_id": len(issues) + 1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                },
                "title": "List of subdomains for '{}' ({} found, HASH: {})".format(
                    asset, len(subdomains_list_clean), subdomains_hash),
                "description": "Subdomain list for '{}': \n\n{}".format(
                    asset, subdomains_str),
                "solution": "n/a",
                "metadata": {
                    "tags": ["domains", "subdomains"]
                },
                "type": "subdomains_enum",
                "raw": subdomains_list_clean,
                "timestamp": ts
            })

    # whois info for domain
    if 'whois' in scan['findings'].keys():
        for asset in scan['findings']['whois'].keys():
            nb_vulns['info'] += 1
            # check errors
            if "errors" in scan['findings']['whois'][asset].keys():
                issues.append({
                    "issue_id": len(issues) + 1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                    },
                    "title": "[Whois] No match for '{}'".format(asset),
                    "description": "No Whois data available for domain '{}'. Note that Whois is available for registered domains only (not sub-domains): \n{}".format(asset, scan['findings']['whois'][asset]['errors']),
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["whois"]
                    },
                    "type": "whois_domain_error",
                    "raw": scan['findings']['whois'][asset]['errors'],
                    "timestamp": ts
                })
            else:
                whois_hash = hashlib.sha1(str(scan['findings']['whois'][asset]['text']).encode("utf-8")).hexdigest()[:6]
                issues.append({
                    "issue_id": len(issues) + 1,
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                    },
                    "title": "Whois info for '{}' (HASH: {})".format(asset, whois_hash),
                    "description": "Whois Info (raw): \n\n{}".format(str(scan['findings']['whois'][asset]['text'])),
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["whois", scan['findings']['whois'][asset]['type']]
                    },
                    "type": f"whois_{scan['findings']['whois'][asset]['type']}_fullinfo",
                    "raw": scan['findings']['whois'][asset]['raw'],
                    "timestamp": ts
                })

        # advanced whois info
        if 'do_advanced_whois' in scan['options'].keys() and scan['options']['do_advanced_whois']:
            for asset in scan['findings']['whois'].keys():
                if "errors" in scan['findings']['whois'][asset].keys():
                    continue

                issue = {
                    "severity": "info", "confidence": "certain",
                    "target": {
                        "addr": [asset],
                        "protocol": "domain"
                    },
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["whois"]
                    },
                    "timestamp": ts
                }

                # status
                nb_vulns['info'] += 1
                whois_statuses = ",\n".join(scan['findings']['whois'][asset]['raw']['status'])
                dom_status = copy.deepcopy(issue) ; dom_status.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_domain_status",
                    "title": "[Whois] '{}' domain has status '{}'".format(asset, scan['findings']['whois'][asset]['raw']['status'][0]),
                    "description": "[Whois] '{}' domain has status '{}'".format(asset, whois_statuses),
                    "raw": scan['findings']['whois'][asset]['raw']['status']
                })
                issues.append(dom_status)

                # registrar
                nb_vulns['info'] += 1
                whois_reginfo = "Name: {}\n".format(scan['findings']['whois'][asset]['raw']['registrar'])
                whois_reginfo += "ID: {}\n".format(scan['findings']['whois'][asset]['raw']['registrar_id'])
                whois_reginfo += "URL(s): {}\n".format(", ".join(scan['findings']['whois'][asset]['raw']['registrar_url']))
                dom_registrar = copy.deepcopy(issue) ; dom_registrar.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_registrar",
                    "title": "[Whois] '{}' domain registrar is '{}'".format(
                        asset, scan['findings']['whois'][asset]['raw']['registrar']),
                    "description": "[Whois] '{}' domain registrar is '{}': \n{}".format(
                        asset, scan['findings']['whois'][asset]['raw']['registrar'],
                        whois_reginfo),
                    "raw": scan['findings']['whois'][asset]['raw']['registrar']
                })
                issues.append(dom_registrar)

                # emails
                if 'emails' in scan['findings']['whois'][asset]['raw'].keys() and scan['findings']['whois'][asset]['raw']['emails']:
                    nb_vulns['info'] += 1
                    dom_emails = copy.deepcopy(issue) ; dom_emails.update({
                        "issue_id": len(issues) + 1,
                        "type": "whois_emails",
                        "title": "[Whois] '{}' domain contact emails are set.".format(asset),
                        "description": "[Whois] '{}' domain contact emails are:\n'{}'".format(
                            asset, ", ".join(scan['findings']['whois'][asset]['raw']['emails'])),
                        "raw": scan['findings']['whois'][asset]['raw']['emails']
                    })
                    issues.append(dom_emails)

                # nameservers
                nb_vulns['info'] += 1
                dom_nameservers = copy.deepcopy(issue) ; dom_nameservers.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_nameservers",
                    "title": "[Whois] '{}' domain nameservers are set.".format(asset),
                    "description": "[Whois] '{}' domain nameservers are:\n{}".format(
                        asset, ",\n".join(scan['findings']['whois'][asset]['raw']['name_servers'])),
                    "raw": scan['findings']['whois'][asset]['raw']['name_servers']
                })
                issues.append(dom_nameservers)

                # updated_date
                nb_vulns['info'] += 1
                update_dates = [d.date().isoformat() for d in scan['findings']['whois'][asset]['raw']['updated_date']]
                dom_updated_dates = copy.deepcopy(issue) ; dom_updated_dates.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_update_dates",
                    "title": "[Whois] '{}' domain was lastly updated the '{}'".format(
                        asset, max(scan['findings']['whois'][asset]['raw']['updated_date']).date().isoformat()),
                    "description": "[Whois] '{}' domain was updated at the following dates: \n\n{}".format(
                        asset, ", ".join(update_dates)),
                    "raw": scan['findings']['whois'][asset]['raw']['updated_date']
                })
                issues.append(dom_updated_dates)

                # creation_date
                nb_vulns['info'] += 1
                dom_created_dates = copy.deepcopy(issue) ; dom_created_dates.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_creation_dates",
                    "title": "[Whois] '{}' domain was lastly created the '{}'".format(
                        asset, scan['findings']['whois'][asset]['raw']['creation_date'].date().isoformat()),
                    "description": "[Whois] '{}' domain was created at the following dates: \n\n{}".format(
                        asset, scan['findings']['whois'][asset]['raw']['creation_date']),
                    "raw": scan['findings']['whois'][asset]['raw']['creation_date']
                })
                issues.append(dom_created_dates)

                # expiry date
                nb_vulns['info'] += 1
                dom_expiration_date = copy.deepcopy(issue) ; dom_expiration_date.update({
                    "issue_id": len(issues) + 1,
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is registred until '{}'".format(
                        asset, scan['findings']['whois'][asset]['raw']['expiration_date'].date().isoformat()),
                    "description": "[Whois] '{}' domain is registred until '{}'".format(
                        asset, scan['findings']['whois'][asset]['raw']['expiration_date'].date().isoformat()),
                    "raw": scan['findings']['whois'][asset]['raw']['expiration_date']
                })
                issues.append(dom_expiration_date)

                # Raise alarms at 6 months (low), 3 months (medium), 2 weeks (high) or when expired (high)
                exp_date = scan['findings']['whois'][asset]['raw']['expiration_date']
                six_month_later = datetime.datetime.now() + datetime.timedelta(days=365/2)
                three_month_later = datetime.datetime.now() + datetime.timedelta(days=90)
                two_weeks_later = datetime.datetime.now() + datetime.timedelta(days=15)

                if exp_date < datetime.datetime.now():
                    nb_vulns['high'] += 1
                    dom_expiration_date_passed = copy.deepcopy(issue) ; dom_expiration_date_passed.update({
                        "issue_id": len(issues) + 1,
                        "severity": "high",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is expired since '{}'".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is expired since '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(exp_date.date().isoformat())
                            # ", ".join(expiry_dates)
                        ),
                        "raw": scan['findings']['whois'][asset]['raw']['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_passed)
                elif exp_date < two_weeks_later:
                    nb_vulns['high'] += 1
                    dom_expiration_date_2w = copy.deepcopy(issue) ; dom_expiration_date_2w.update({
                        "issue_id": len(issues) + 1,
                        "severity": "high",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(exp_date.date().isoformat())
                            # ", ".join(expiry_dates)
                        ),
                        "raw": scan['findings']['whois'][asset]['raw']['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_2w)
                elif exp_date < three_month_later:
                    nb_vulns['medium'] += 1
                    dom_expiration_date_3m = copy.deepcopy(issue) ; dom_expiration_date_3m.update({
                        "issue_id": len(issues) + 1,
                        "severity": "medium",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 3 months)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 3 months)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(exp_date.date().isoformat())
                            # ", ".join(expiry_dates)
                        ),
                        "raw": scan['findings']['whois'][asset]['raw']['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_3m)
                elif exp_date < six_month_later:
                    nb_vulns['low'] += 1
                    dom_expiration_date_6m = copy.deepcopy(issue) ; dom_expiration_date_6m.update({
                        "issue_id": len(issues) + 1,
                        "severity": "low",
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}' (less than 6 months)".format(
                            asset, exp_date.date().isoformat()),
                        "description": "[Whois] '{}' domain is registred until '{}' (less than 6 months)\n\nAll dates in record: {}".format(
                            asset,
                            exp_date.date().isoformat(),
                            ", ".join(exp_date.date().isoformat())
                            # ", ".join(expiry_dates)
                        ),
                        "raw": scan['findings']['whois'][asset]['raw']['expiration_date'],
                        "solution": "Renew the domain"
                    })
                    issues.append(dom_expiration_date_6m)

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "owl_dns",
        "engine_version": this.scanner["version"]
    }

    return issues, summary


@app.route('/engines/owl_dns/getfindings/<scan_id>')
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    # check if the scan is finished
    # status()
    scan_status(scan_id)
    if this.scans[scan_id]['status'] != "FINISHED":
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not finished (status={this.scans[scan_id]['status']})"})
        return jsonify(res)

    issues, summary = _parse_results(scan_id)
    scan = {
        "scan_id": scan_id
    }

    # Store the findings in a file
    with open(f"{BASE_DIR}/results/owl_dns_{scan_id}.json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file, default=_json_serial)

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({"scan": scan_id, "summary": summary, "issues": issues, "status": "success"})
    return jsonify(res)


@app.route('/engines/owl_dns/getreport/<scan_id>')
def getreport(scan_id):
    filepath = f"{BASE_DIR}/results/owl_dns_{scan_id}.json"

    if not os.path.exists(filepath):
        return jsonify({"status": "error", "reason": f"report file for scan_id '{scan_id}' not found"})

    return send_from_directory(f"{BASE_DIR}/results/", "owl_dns_{scan_id}.json")


def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


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
        res += urllib.request.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

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
    if sys.platform == "darwin":
        os.environ['OBJC_DISABLE_INITIALIZE_FORK_SAFETY'] = 'YES'

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
        help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
