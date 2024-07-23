#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import hashlib
import threading
import datetime
import copy
import dns.resolver
import socket
import optparse
import random
import string
import validators
import requests
import whois
from ipwhois import IPWhois
from modules.dnstwist import DnsTwist
from modules.dkimsignatures import dkimlist
import re
import urllib
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, redirect, request, send_from_directory, url_for
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

from etc.issues import spf_issues

# Own library imports
# sys.path.append("./PatrowlEnginesUtils/")
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine

app = Flask(__name__)
APP_DEBUG = os.environ.get("DEBUG", "").lower() in ["true", "1", "yes", "y", "on"]
APP_MAXSCANS = int(os.environ.get("APP_MAXSCANS", 10))

APP_HOST = "0.0.0.0"
APP_PORT = 5006
APP_ENGINE_NAME = "owl_dns"

APP_TIMEOUT = int(os.environ.get("APP_TIMEOUT", 3600))
APP_WF_MAX_PAGE = int(os.environ.get("APP_WF_MAX_PAGE", 10))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]

ENGINE_TIME_OUT = 5.0

engine = PatrowlEngine(
    app=app, base_dir=BASE_DIR, name=APP_ENGINE_NAME, max_scans=APP_MAXSCANS
)
this.engine = engine


engine.metadata["scan_lock"] = threading.RLock()
engine.metadata["wf_apitokens"] = []
engine.metadata["resolver"] = dns.resolver.Resolver()
engine.metadata["resolver"].timeout = ENGINE_TIME_OUT
engine.metadata["resolver"].lifetime = ENGINE_TIME_OUT
list_nameservers = os.environ.get("NAMESERVER", "8.8.8.8,8.8.4.4").split(",")
engine.metadata["resolver"].nameservers = list_nameservers
#
engine.metadata["pool"] = ThreadPoolExecutor(5)


def get_random_string(n=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


@app.route("/")
def default():
    return engine.default()


@app.route("/engines/owl_dns/")
def index():
    return engine.index()


@app.route("/engines/owl_dns/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/owl_dns/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/owl_dns/info")
def info():
    """Get info on running engine."""
    return engine.info()


def _engine_is_busy():
    """Returns if engine is busy scanning."""
    return engine._engine_is_busy()


def _loadconfig():
    conf_file = f"{BASE_DIR}/owl_dns.json"
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
        engine.scanner["status"] = "READY"
        sys.path.append(engine.scanner["sublist3r_bin_path"])
        globals()["sublist3r"] = __import__("sublist3r")
        DnsTwist(engine.scanner["dnstwist_bin_path"])

    else:
        app.logger.error(f"Error: config file '{conf_file}' not found")
        return {"status": "error", "reason": "config file not found"}

    if not os.path.isfile(engine.scanner["seg_path"]):
        engine.scanner["status"] = "ERROR"
        app.logger.error("Error: path to Secure Email Gateway providers not found")
        return {
            "status": "ERROR",
            "reason": "path to Secure Email Gateway providers not found.",
        }

    if not os.path.isfile(engine.scanner["external_ip_ranges_path"]):
        engine.scanner["status"] = "ERROR"
        app.logger.error(
            "Error: path to external IP ranges (CDN, WAF, Cloud) not found"
        )
        return {
            "status": "ERROR",
            "reason": "path to external IP ranges (CDN, WAF, Cloud) not found.",
        }

    engine.metadata["wf_apitokens"] = []
    for apikey in engine.scanner["whoisfreak_api_tokens"]:
        engine.metadata["wf_apitokens"].append(apikey)
    del engine.scanner["whoisfreak_api_tokens"]

    version_filename = f"{BASE_DIR}/VERSION"
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        engine.scanner["version"] = version_file.read().rstrip("\n")
        version_file.close()


@app.route("/engines/owl_dns/reloadconfig")
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/owl_dns/startscan", methods=["POST"])
def start_scan():
    # @todo: validate parameters and options format
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS * 2:
        res.update(
            {
                "status": "error",
                "reason": "Scan refused: max concurrent active scans reached ({})".format(
                    APP_MAXSCANS
                ),
            }
        )
        return jsonify(res), 503

    data = json.loads(request.data)
    if "assets" not in data.keys():
        res.update(
            {
                "status": "refused",
                "details": {"reason": "arg error, something is missing ('assets' ?)"},
            }
        )
        return jsonify(res), 503

    scan_id = str(data["scan_id"])

    engine.scans.update(
        {
            scan_id: {
                "status": "STARTED",
                "started_at": int(time.time() * 1000),
                "assets": data["assets"],
            }
        }
    )

    status()
    if engine.scanner["status"] != "READY":
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": "scanner not ready",
                    "status": engine.scanner["status"],
                },
            }
        )
        engine.scans.update(
            {
                scan_id: {
                    "status": "ERROR",
                }
            }
        )
        engine.scans.pop(scan_id, None)
        return jsonify(res), 503

    # Sanitize args :
    scan = {
        "assets": data["assets"],
        "threads": [],
        "futures": [],
        "dnstwist": {},
        "position": data.get("position", 0),
        "root_scan_id": data.get("root_scan_id", 0),
        "options": data.get("options", {}),
        "scan_id": scan_id,
        "status": "STARTED",
        "started_at": int(time.time() * 1000),
        "findings": {},
    }

    engine.scans.update({scan_id: scan})

    if "do_whois" in scan["options"].keys() and data["options"]["do_whois"]:
        for asset in data["assets"]:
            if asset["datatype"] in ["domain", "ip", "fqdn"]:
                th = engine.metadata["pool"].submit(_get_whois, scan_id, asset["value"])
                engine.scans[scan_id]["futures"].append(th)

    if (
        "do_advanced_whois" in scan["options"].keys()
        and data["options"]["do_advanced_whois"]
    ):
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(_get_whois, scan_id, asset["value"])
                engine.scans[scan_id]["futures"].append(th)

    # subdomains enumeration using search engines, VT and public PassiveDNS API
    if (
        "do_subdomain_enum" in scan["options"].keys()
        and data["options"]["do_subdomain_enum"]
    ):
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(
                    _subdomain_enum, scan_id, asset["value"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if (
        "do_subdomains_resolve" in scan["options"].keys()
        and data["options"]["do_subdomains_resolve"]
    ):
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(
                    _dns_resolve, scan_id, asset["value"], True
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_dns_resolve" in scan["options"].keys() and data["options"]["do_dns_resolve"]:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(
                    _dns_resolve, scan_id, asset["value"], False
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_seg_check" in scan["options"].keys() and data["options"]["do_seg_check"]:
        for asset in data["assets"]:
            if asset["datatype"] in ["domain", "fqdn"]:
                th = engine.metadata["pool"].submit(
                    _do_seg_check, scan_id, asset["value"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_spf_check" in scan["options"].keys() and data["options"]["do_spf_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(
                    target=_do_spf_check, args=(scan_id, asset["value"])
                )
                th.start()
                engine.scans[scan_id]["threads"].append(th)

    if "do_dkim_check" in scan["options"].keys() and data["options"]["do_dkim_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(
                    target=_do_dkim_check, args=(scan_id, asset["value"])
                )
                th.start()
                engine.scans[scan_id]["threads"].append(th)

    if "do_dmarc_check" in scan["options"].keys() and data["options"]["do_dmarc_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = threading.Thread(
                    target=_do_dmarc_check, args=(scan_id, asset["value"])
                )
                th.start()
                engine.scans[scan_id]["threads"].append(th)

    if (
        "do_subdomain_bruteforce" in scan["options"].keys()
        and data["options"]["do_subdomain_bruteforce"]
    ):
        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(
                    _subdomain_bruteforce, scan_id, asset["value"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_reverse_dns" in scan["options"].keys() and data["options"]["do_reverse_dns"]:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = engine.metadata["pool"].submit(
                    _reverse_dns, scan_id, asset["value"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if (
        "do_dnstwist_subdomain_search" in scan["options"].keys()
        and data["options"]["do_dnstwist_subdomain_search"]
    ):
        options = {
            "tld": False,
            "check_ssdeep": False,
            "check_geoip": False,
            "check_mx": False,
            "check_whois": False,
            "check_banners": False,
        }

        # Dictionary to map option names to their variables and initial values
        options_mapping = {
            "dnstwist_check_tld": ("tld", engine.scanner["dnstwist_common_tlds"]),
            "dnstwist_check_ssdeep": ("check_ssdeep", True),
            "dnstwist_check_geoip": ("check_geoip", True),
            "dnstwist_check_mx": ("check_mx", True),
            "dnstwist_check_whois": ("check_whois", True),
            "dnstwist_check_banners": ("check_banners", True),
        }

        # Check if options should be tested
        for option, (var_name, value) in options_mapping.items():
            if option in scan["options"].keys() and data["options"].get(option):
                options[var_name] = value

        timeout = APP_TIMEOUT
        if "max_timeout" in scan["options"].keys() and data["options"]["max_timeout"]:
            timeout = data["options"]["max_timeout"]

        for asset in data["assets"]:
            if asset["datatype"] == "domain":
                th = engine.metadata["pool"].submit(
                    DnsTwist.search_subdomains,
                    asset["value"],
                    options["tld"],
                    options["check_ssdeep"],
                    options["check_geoip"],
                    options["check_mx"],
                    options["check_whois"],
                    options["check_banners"],
                    timeout,
                )
                engine.scans[scan_id]["dnstwist"][asset["value"]] = {}
                engine.scans[scan_id]["futures"].append(th)

    if (
        "do_reverse_whois" in scan["options"].keys()
        and data["options"]["do_reverse_whois"]
    ):
        for asset in data["assets"]:
            if asset["datatype"] in ["domain", "fqdn", "keyword", "email"]:
                th = engine.metadata["pool"].submit(
                    _reverse_whois, scan_id, asset["value"], asset["datatype"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_cdn_check" in scan["options"].keys() and data["options"]["do_cdn_check"]:
        for asset in data["assets"]:
            if asset["datatype"] in ["ip", "domain", "fqdn"]:
                th = engine.metadata["pool"].submit(
                    _cdn_check, scan_id, asset["value"], asset["datatype"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_waf_check" in scan["options"].keys() and data["options"]["do_waf_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = engine.metadata["pool"].submit(
                    _waf_check, scan_id, asset["value"], asset["datatype"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_cloud_check" in scan["options"].keys() and data["options"]["do_cloud_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = engine.metadata["pool"].submit(
                    _cloud_check, scan_id, asset["value"], asset["datatype"]
                )
                engine.scans[scan_id]["futures"].append(th)

    if "do_saas_check" in scan["options"].keys() and data["options"]["do_saas_check"]:
        for asset in data["assets"]:
            if asset["datatype"] == "ip":
                th = engine.metadata["pool"].submit(
                    _saas_check, scan_id, asset["value"], asset["datatype"]
                )
                engine.scans[scan_id]["futures"].append(th)

    res.update({"status": "accepted", "details": {"scan_id": scan["scan_id"]}})

    return jsonify(res)


def __is_ip_addr(host):
    res = False
    try:
        res = socket.gethostbyname(host) == host
    except Exception as e:
        app.logger.error(f"__is_ip_addr({host}): failed: {e}")
    return res


def __is_domain(host):
    res = False
    try:
        res = validators.domain(host) is True
    except Exception as e:
        app.logger.error(f"__is_domain({host}): failed: {e}")
    return res


def _get_wf_reverse_url(apikey: str, type: str, value: str):
    return f"https://api.whoisfreaks.com/v1.0/whois?apiKey={apikey}&whois=reverse&{type}={value}&mode=mini"


def _get_wf_whois(apikey: str, value: str):
    w = None
    resp = requests.get(
        f"https://api.whoisfreaks.com/v1.0/whois?apiKey={apikey}&whois=live&domainName={value}"
    )
    if resp.status_code != 200:
        app.logger.debug("_get_wf_whois", value, resp.status_code)
        return w

    return json.loads(resp.text)


def _get_wf_domains(wf_url: str, max_pages: int):
    wf_domains = []
    page = 1
    resp = requests.get(wf_url + f"&page={page}")
    if resp.status_code != 200:
        app.logger.debug("_get_wf_domains", wf_url, resp.status_code)
        return wf_domains

    # get results from page 1
    results = json.loads(resp.text)
    if "whois_domains_historical" not in results.keys():
        return wf_domains
    for d in results["whois_domains_historical"]:
        wf_domains.append(d["domain_name"])

    if results["total_Pages"] < max_pages:
        max_pages = results["total_Pages"]

    # while results['total_Pages'] > page and page < 10:
    while max_pages > page:
        time.sleep(1)
        page += 1
        resp = requests.get(wf_url + f"&page={page}")
        if resp.status_code == 200:
            page_results = json.loads(resp.text)
            for d in page_results["whois_domains_historical"]:
                wf_domains.append(d["domain_name"])
    return wf_domains


def _reverse_whois(scan_id, asset, datatype):
    res = {}
    domains = []
    if len(engine.metadata["wf_apitokens"]) == 0:
        # No whoisfreak API Token available
        return res

    # Select an API KEY
    apikey = engine.metadata["wf_apitokens"][
        random.randint(0, len(engine.metadata["wf_apitokens"]) - 1)
    ]

    # Check the asset is a valid domain name or IP Address
    if datatype in ["domain", "fqdn"]:
        if not __is_domain(asset):
            return res
        w = whois.whois(asset)
        # w = whois.query(asset, force=True)
        # print(w.name, w.registrant, w.owner)

        # if w.domain_name is None:
        #     return res
        # wf_value = ""
        # # Get the registrant organization if available, otherwise try to get the registrant name
        # if 'org' in w.keys() and w['org'] not in ["", None]:
        #     wf_value = w['org'].lower()
        # elif 'registrant_name' in w.keys() and w['registrant_name'] not in ["", None]:
        #     wf_value = w['registrant_name'].lower()
        if w.domain_name is None:
            return res
        wf_value = ""
        # Get the registrant organization if available, otherwise try to get the registrant name
        if w.registrant.lower() not in ["", None, "redacted for privacy"]:
            wf_value = w.registrant.lower()

        if wf_value == "":
            return res

        # w = _get_wf_whois(apikey, asset)
        # if w is None:
        #     return res

        # print(w)
        # # if "registrant_contact" in w.keys() and w['registrant_contact']
        # if w["registrant"].lower() not in ["", None, "redacted for privacy"]:
        #     wf_value = w.registrant.lower()

        wf_types = ["company", "owner"]
    elif datatype in ["keyword", "email"]:
        # print(asset)
        if validators.email(asset):
            wf_types = ["email"]
        else:
            wf_types = ["keyword", "owner", "company"]
        wf_value = asset
    else:
        return res

    # Limit max pages to rationalize credit usage
    max_pages = APP_WF_MAX_PAGE
    if (
        "reverse_whois_max_pages" in engine.scans[scan_id]["options"].keys()
        and isinstance(engine.scans[scan_id]["options"]["reverse_whois_max_pages"], int)
        and engine.scans[scan_id]["options"]["reverse_whois_max_pages"] > 0
    ):
        max_pages = engine.scans[scan_id]["options"]["reverse_whois_max_pages"]

    try:
        for wf_type in wf_types:
            wf_url = _get_wf_reverse_url(apikey, wf_type, wf_value)
            wf_domains = _get_wf_domains(wf_url, max_pages)
            domains.extend(wf_domains)
    except Exception:
        if len(domains) == 0:
            return res

    if len(domains) == 0:
        return res

    # Remove duplicates
    domains = list(set(domains))
    res = {asset: {"domains": domains, "types": wf_types, "value": wf_value}}

    scan_lock = threading.RLock()
    with scan_lock:
        if "reverse_whois" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["reverse_whois"] = {}
        if bool(res):
            engine.scans[scan_id]["findings"]["reverse_whois"].update(res)

    return res


def is_ipaddr_in_subnet(ip: str, subnet: str) -> bool:
    """Check if the IP address is part of the subnet"""
    try:
        if IPAddress(ip) in IPNetwork(subnet):
            return True
    except (TypeError, ValueError, AddrFormatError):
        pass
    return False


def _check_ip(ip: str, record_types: list = []) -> dict:
    """Check IP from CDN, WAF, Cloud, SaaS providers public records."""

    with open(engine.scanner["external_ip_ranges_path"]) as all_data_file:
        all_data = json.loads(all_data_file.read())

    all_data_types = all_data.keys()  # ["cdn", "waf", "cloud", "parking", "saas"]
    data_types = []
    ip_provider = ""

    if len(record_types) > 0:
        for record_type in record_types:
            if record_type in all_data.keys():
                data_types.append(record_type)
    else:
        data_types = all_data_types

    for data_type in data_types:
        for provider in all_data[data_type].keys():
            for subnet in all_data[data_type][provider]["ipv4"]:
                if is_ipaddr_in_subnet(ip, subnet):
                    ip_provider = provider
                    break

    if ip_provider == "":  # no results
        return {}
    return {"attributes": data_types, "provider": ip_provider}


def __get_ip_targets(asset: str, datatype: str) -> list:
    targets = []
    if datatype == "ip":
        targets = [asset]
    elif datatype in ["domain", "fqdn"]:
        try:
            targets = socket.gethostbyname_ex(asset)[2]
        except Exception:
            return []

    return targets


def _cdn_check(scan_id: str, asset: str, datatype: str) -> dict:
    targets = __get_ip_targets(asset, datatype)

    if len(targets) == 0:
        return {}

    for target in targets:
        res = _check_ip(target, ["cdn"])

        scan_lock = threading.RLock()
        with scan_lock:
            if "cdn_check" not in engine.scans[scan_id]["findings"].keys():
                engine.scans[scan_id]["findings"]["cdn_check"] = {}
            if bool(res):
                engine.scans[scan_id]["findings"]["cdn_check"].update({asset: res})

    return res


def _waf_check(scan_id: str, asset: str, datatype: str) -> dict:
    targets = __get_ip_targets(asset, datatype)

    if len(targets) == 0:
        return {}

    for target in targets:
        res = _check_ip(target, ["waf"])

        scan_lock = threading.RLock()
        with scan_lock:
            if "waf_check" not in engine.scans[scan_id]["findings"].keys():
                engine.scans[scan_id]["findings"]["waf_check"] = {}
            if bool(res):
                engine.scans[scan_id]["findings"]["waf_check"].update({asset: res})

    return res


def _cloud_check(scan_id: str, asset: str, datatype: str) -> dict:
    targets = __get_ip_targets(asset, datatype)

    if len(targets) == 0:
        return {}

    for target in targets:
        res = _check_ip(target, ["cloud"])

        scan_lock = threading.RLock()
        with scan_lock:
            if "cloud_check" not in engine.scans[scan_id]["findings"].keys():
                engine.scans[scan_id]["findings"]["cloud_check"] = {}
            if bool(res):
                engine.scans[scan_id]["findings"]["cloud_check"].update({asset: res})

    return res


def _saas_check(scan_id: str, asset: str, datatype: str) -> dict:
    targets = __get_ip_targets(asset, datatype)

    if len(targets) == 0:
        return {}

    for target in targets:
        res = _check_ip(target, ["saas"])

        scan_lock = threading.RLock()
        with scan_lock:
            if "saas_check" not in engine.scans[scan_id]["findings"].keys():
                engine.scans[scan_id]["findings"]["saas_check"] = {}
            if bool(res):
                engine.scans[scan_id]["findings"]["saas_check"].update({asset: res})

    return res


def _do_seg_check(scan_id, asset_value):
    seg_dict = []
    dns_records = _dns_resolve_asset(asset_value, "MX")
    has_seg = False

    if len(dns_records) == 0:
        # seg_dict = {"status": "failed", "reason": f"no MX records found for asset '{asset_value}'"}
        return

    with open(engine.scanner["seg_path"]) as seg_providers_file:
        seg_providers = json.loads(seg_providers_file.read())["seg"]

    for dns_record in dns_records:
        for dns_value in dns_record["values"]:
            for seg_provider in seg_providers.keys():
                for mx_record in seg_providers[seg_provider]["mx_records"]:
                    if dns_value.endswith(mx_record):
                        seg_dict.append({seg_provider: seg_providers[seg_provider]})
                        has_seg = True
                        break

    scan_lock = threading.RLock()
    with scan_lock:
        if "seg_dict" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["seg_dict"] = {}
            engine.scans[scan_id]["findings"]["seg_dict_dns_records"] = {}

        if asset_value not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["seg_dict"][asset_value] = {}
            engine.scans[scan_id]["findings"]["seg_dict_dns_records"][asset_value] = {}

        if has_seg is True:
            engine.scans[scan_id]["findings"]["seg_dict"][asset_value] = copy.deepcopy(
                seg_dict
            )
            engine.scans[scan_id]["findings"]["seg_dict_dns_records"][asset_value] = (
                copy.deepcopy(dns_records)
            )
        else:
            engine.scans[scan_id]["findings"]["no_seg"] = {
                asset_value: "MX records found but no Secure Email Gateway set"
            }


def _do_dmarc_check(scan_id, asset_value):
    dmarc_dict = {"no_dmarc_record": "info"}
    dns_records = _dns_resolve_asset(asset_value, "TXT")
    for record in dns_records:
        for value in record["values"]:
            if "DMARC" in value:
                dmarc_dict.pop("no_dmarc_record")
                if "p=none" in value:
                    dmarc_dict["insecure_dmarc_policy"] = "high"
                if "sp=none" in value:
                    dmarc_dict["insecure_dmarc_subdomain_sp"] = "high"
                for word in value.split(" "):
                    if "pct=" in word:
                        num = int(re.sub("\D", "", word))
                        if num < 100:
                            dmarc_dict["dmarc_partial_coverage"] = "medium"

    with engine.metadata["scan_lock"]:
        engine.scans[scan_id]["findings"]["dmarc_dict"] = {asset_value: dmarc_dict}
        engine.scans[scan_id]["findings"]["dmarc_dict_dns_records"] = {
            asset_value: dns_records
        }


def _do_dkim_check(scan_id, asset_value):
    dkim_dict = {}
    found_dkim = False
    dkim_found_list = {}
    for selector in dkimlist:
        dkim_record = selector + "._domainkey." + asset_value
        dns_records = _dns_resolve_asset(dkim_record)
        if len(dns_records) > 0:
            found_dkim = True
            for dns_record in dns_records:
                for value in dns_record["values"]:
                    dkim_found_list[selector] = value
    if not found_dkim:
        dkim_dict["dkim"] = "couldn't find the selector in our list"
    else:
        dkim_dict["dkim"] = dkim_found_list

    with engine.metadata["scan_lock"]:
        engine.scans[scan_id]["findings"]["dkim_dict"] = {asset_value: dkim_dict}
        engine.scans[scan_id]["findings"]["dkim_dict_dns_records"] = {
            asset_value: dns_records
        }


def _do_spf_check(scan_id: int, asset_value: str) -> None:
    """Check SPF record lookup"""
    dns_txt_records = _dns_resolve_asset(asset_value, "TXT")
    answers = dns_txt_records[0].get("answers") if dns_txt_records else []
    # Parses SPF records
    parsed_spf_record, issues = _parse_spf_record(answers)

    # Issue: DEPRECATED_SPF_RECORD
    dns_spf_records = _dns_resolve_asset(asset_value, "SPF")
    if dns_spf_records:
        issues.append(spf_issues.DEPRECATED_SPF_RECORD)

    # Issue: DNS_LOOKUP_LIMIT
    dns_lookup_limit = 10
    try:
        dns_lookup_count, spf_lookup_records = get_lookup_count_and_spf_records(
            domain=asset_value
        )
    except RecursionError as error:
        app.logger.info(
            f"RecursionError on {asset_value} with get_lookup_count_and_spf_records: {error}"
        )
        issues.append(
            dict(
                spf_issues.DNS_LOOKUP_LIMIT,
                extra_info=f"More than {sys.getrecursionlimit()} DNS lookups are required to validate SPF record.",
            )
        )
    else:
        if dns_lookup_count > dns_lookup_limit:
            issues.append(
                dict(
                    spf_issues.DNS_LOOKUP_LIMIT,
                    value=spf_lookup_records[0] if spf_lookup_records else "",
                    extra_info=f"{dns_lookup_count} DNS lookups are required to validate SPF record.",
                )
            )

    with engine.metadata["scan_lock"]:
        engine.scans[scan_id]["findings"].setdefault("spf_issues", {})
        engine.scans[scan_id]["findings"]["spf_issues"][asset_value] = {
            "issues": issues,
            "parsed_spf_record": parsed_spf_record,
        }


def _parse_spf_record(dns_records: list[str]) -> tuple[list, list]:
    # Basic mechanisms, they contribute to the language framework.
    # They do not specify a particular type of authorization scheme.
    basic_mechanisms = ["all", "include"]
    # Designated sender mechanisms, they are used to designate a set of <ip> addresses as being permitted or
    # not permitted to use the <domain> for sending mail.
    designed_sender_mechanisms = ["a", "mx", "ptr", "ip4", "ip6", "exists"]

    spf_record_count = 0
    issues = []

    for dns_record in dns_records:
        value = dns_record.removeprefix('"').removesuffix('"').replace('" "', "")
        # Check the version
        if "v=spf1" not in value.lower():
            continue
        spf_record_count += 1

        # Issue: MALFORMED_SPF_RECORD
        if value[0] == " ":
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="There is an extra space before the start of the string.",
                )
            )
            value = value.lstrip(" ")
        # Check for extra spaces after the end of the string
        if value[-1] == " ":
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="There is an extra space after the end of the string.",
                )
            )
            value = value.rstrip(" ")
        # Check for quoted TXT record
        if value[0] == '"' or value[-1] == '"':
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="The SPF record is surrounded quotation marks.",
                )
            )
            value = value.strip('"')

        # Issue: DIRECTIVES_AFTER_ALL
        directives_after_all = re.search(r"[-~?+]?all (.+)", value)
        if directives_after_all:
            issues.append(
                dict(
                    spf_issues.DIRECTIVES_AFTER_ALL,
                    value=value,
                    extra_info=f'These directives after "all" are ignored: {directives_after_all.group(1)}.',
                )
            )

        # Issue: STRING_TOO_LONG
        maximum_string_length = 255
        for character_string in dns_record.strip('"').split('" "'):
            if len(character_string) > maximum_string_length:
                issues.append(
                    dict(
                        spf_issues.STRING_TOO_LONG,
                        value=value,
                        extra_info=f"This part is {len(character_string)} characters long, "
                        f"and therefore too long: {character_string}.",
                    )
                )
                continue

        # List of directives
        spf_directives = value.split()
        spf_directives.pop(0)  # version is not a directive, remove it from directives

        # Issue: MISS_SPF_RECORD_TERMINATION
        if not re.search(r"[-~?+]?(all|redirect=)", spf_directives[-1].lower()):
            issues.append(dict(spf_issues.MISS_SPF_RECORD_TERMINATION, value=value))

        for spf_directive in spf_directives:
            directive_qualifier = "+"  # qualifier is optional, and defaults to "+"
            directive_value = ""
            if "=" in spf_directive:  # Modifiers, and not mechanisms
                directive_type, directive_value = spf_directive.split("=")
                directive_type = directive_type.lower()
                directive_value = directive_value.lower()
                parsed_spf_record.append([directive_qualifier, directive_type, directive_value])
                # Unrecognized modifiers MUST be ignored
                continue
            if ":" in spf_directive:  # Mechanisms with value
                directive_type, directive_value = spf_directive.split(":")
                directive_type = directive_type.lower()
                directive_value = directive_value.lower()
            else:  # Mechanisms without value
                directive_type = spf_directive.lower()
            if directive_type.startswith(("-", "~", "?", "+")):
                directive_qualifier = directive_type[0]
                directive_type = directive_type[1:].lower()

            if directive_type not in basic_mechanisms + designed_sender_mechanisms:
                issues.append(
                    dict(
                        spf_issues.MALFORMED_SPF_RECORD,
                        value=value,
                        extra_info=f"'{directive_type}' is an illegal term.",
                    )
                )

            if directive_type == "ptr":
                issues.append(dict(spf_issues.PRESENCE_OF_PTR, value=value))
            elif directive_type == "all" and directive_qualifier in ["?", "+"]:
                issues.append(dict(spf_issues.PERMISSIVE_SPF_RECORD, value=value))

            parsed_spf_record.append([directive_qualifier, directive_type, directive_value])

    # Issue: NO_SPF_RECORD
    if spf_record_count == 0:
        issues.append(
            dict(
                spf_issues.NO_SPF_RECORD,
                extra_info=(
                    f"Other DNS TXT records are: {', '.join(dns_records)}."
                    if dns_records
                    else "There is no DNS TXT record."
                ),
            )
        )
    # Issue: MULTIPLE_SPF_RECORDS
    elif spf_record_count > 1:
        issues.append(
            dict(
                spf_issues.MULTIPLE_SPF_RECORDS,
                extra_info=f"Other DNS TXT records are: {', '.join(dns_records)}.",
            )
        )

    return parsed_spf_record, issues


def get_lookup_count_and_spf_records(domain: str) -> tuple[int, list[tuple[str, str]]]:
    """Count the numbers of DNS queries during SPF evaluation and retrieve the SPF records

    The following terms cause DNS queries: the "include", "a", "mx", "ptr", and "exists" mechanisms, and the "redirect"
    modifier. SPF implementations MUST limit the total number of those terms to 10 during SPF evaluation, to avoid
    an unreasonable load on the DNS.

    :param domain: A domain name
    :return: Number of DNS queries during SPF evaluation, and the list of SPF records queried
    """
    dns_records = _dns_resolve_asset(domain, "TXT")
    if not dns_records:
        return 0, []

    spf_records = list(
        filter(
            lambda dns_record: dns_record.lower().startswith("v=spf1"),
            dns_records[0].get("values"),
        )
    )
    if not spf_records:
        return 0, []

    spf_record = spf_records[0]
    lookup_domains = re.findall(
        r"\b[+\-~?]?(?:include:|redirect=)(\S+)\b", spf_record, re.IGNORECASE
    )
    other_terms_count = len(
        re.findall(r"\b[+\-~?]?(a|mx|ptr|exists):?\b", spf_record, re.IGNORECASE)
    )
    if not lookup_domains:
        return other_terms_count, [(domain, spf_record)]

    dns_lookup_count = len(lookup_domains) + other_terms_count
    spf_lookup_records = [(domain, spf_record)]
    for lookup_domain in lookup_domains:
        domain_dns_lookup_count, domain_spf_lookup_records = (
            get_lookup_count_and_spf_records(lookup_domain)
        )
        dns_lookup_count += domain_dns_lookup_count
        spf_lookup_records.extend(domain_spf_lookup_records)

    return dns_lookup_count, spf_lookup_records


def _dns_resolve(scan_id, asset, check_subdomains=False):
    scan_lock = threading.RLock()
    with scan_lock:
        if "dns_resolve" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["dns_resolve"] = {}
        engine.scans[scan_id]["findings"]["dns_resolve"][asset] = {}
        engine.scans[scan_id]["findings"]["dns_resolve"][asset] = copy.deepcopy(
            _dns_resolve_asset(asset)
        )
    return engine.scans[scan_id]["findings"]["dns_resolve"][asset]


def _dns_resolve_asset(
    asset: str, type_of_record: str = None
) -> list[dict[str, str | list[str]]]:
    sub_res = []
    record_types = ["CNAME", "A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV"]
    if type_of_record:
        record_types = [type_of_record]
    for record_type in record_types:
        try:
            answers = engine.metadata["resolver"].query(asset, record_type)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            app.logger.error(
                f"DNS resolve raises an exception for asset '{asset}': {e}"
            )
        else:
            sub_res.append(
                {
                    "record_type": record_type,
                    "values": [
                        str(rdata).strip('"').replace('" "', " ") for rdata in answers
                    ],
                    "answers": [str(rdata) for rdata in answers],
                }
            )

    return sub_res


def _reverse_dns(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_ip_addr(asset):
        return res

    try:
        answers = engine.metadata["resolver"].query(
            dns.reversename.from_address(asset), "PTR"
        )
        res.update({asset: [str(rdata) for rdata in answers]})
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass

    scan_lock = threading.RLock()
    with scan_lock:
        if "reverse_dns" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["reverse_dns"] = {}
        if bool(res):
            engine.scans[scan_id]["findings"]["reverse_dns"].update(res)

    return res


def _get_whois(scan_id, asset):
    res = {}
    is_domain = __is_domain(asset)
    is_ip = __is_ip_addr(asset)

    # print(asset, is_domain, is_ip)

    # Check the asset is a valid domain name or IP Address
    if not is_domain and not is_ip:
        return res

    if is_domain:
        w = whois.whois(asset)
        # w = whois.query(asset, force=True)
        # print(w.__dict_)
        if w.domain_name is None:
            res.update({asset: {"errors": w}})
        else:
            res.update(
                {
                    asset: {
                        "raw": {"dict": w, "text": w.text},
                        "text": w.text,
                        "type": "domain",
                    }
                }
            )
    if is_ip:
        w = IPWhois(str(asset).strip()).lookup_rdap()
        w_text = "see raw"
        try:
            w_text = json.dumps(w, sort_keys=True)
        except Exception:
            pass

        res.update(
            {
                asset: {
                    "raw": {"dict": w, "text": w_text},
                    "text": w_text,
                    "type": "ip",
                }
            }
        )

    scan_lock = threading.RLock()
    with scan_lock:
        if "whois" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["whois"] = {}
        if bool(res):
            engine.scans[scan_id]["findings"]["whois"].update(res)

    return res


def _subdomain_bruteforce(scan_id, asset):
    res = {}
    SUB_LIST = [
        "www",
        "www1",
        "www2",
        "www3",
        "m",
        "mob",
        "mobile",
        "ftp",
        "ftp1",
        "ftp2",
        "ftp3",
        "sftp",
        "mail",
        "mail1",
        "mail2",
        "mail3",
        "webmail",
        "smtp",
        "mx",
        "email",
        "owa",
        "imap",
        "prod",
        "dev",
        "pro",
        "test",
        "demo",
        "demo1",
        "demo2",
        "beta",
        "pre-prod",
        "preprod",
        "int",
        "acc",
        "uat",
        "stg",
        "intra",
        "intranet",
        "internal",
        "backup",
        "backups",
        "share",
        "db",
        "db1",
        "db2",
        "data",
        "mysql",
        "oracle",
        "pg",
        "ldap",
        "ldap2",
        "open",
        "survey",
        "remote",
        "blog",
        "blogs",
        "server",
        "git",
        "sys",
        "svn",
        "ns",
        "ns1",
        "ns2",
        "dns",
        "dns1",
        "dns2",
        "vpn",
        "vpn2",
        "support",
        "web",
        "api",
        "cdn",
        "ssh",
        "admin",
        "adm",
        "int",
        "rec",
        "recette",
        "re7",
        "pp",
        "stag",
        "staging",
        "video",
        "videos",
        "mob",
        "mobile",
        "mobi",
        "ws",
        "ad",
        "doc",
        "docs",
        "new",
        "news",
        "mysql",
        "db",
        "cpanel",
        "static",
        "store",
        "feeds",
        "rss",
        "files",
        "mantis",
        "nagios",
        "outlook",
        "zabbix",
        "it",
        "pt",
        "es",
        "uk",
        "us",
        "pt",
        "ir",
        "ch",
        "de",
        "br",
        "in",
    ]

    # Check wildcard domain
    w_domain = "{}.{}".format(get_random_string(), asset)
    if len(_dns_resolve_asset(w_domain)) > 0:
        return res

    valid_sudoms = []
    for sub in SUB_LIST:
        subdom = ".".join((sub, asset))
        results = _dns_resolve_asset(subdom)

        if len(results) > 0:
            valid_sudoms.append(subdom)

    # add the subdomain in scan['findings']['subdomains_list'] if not exists
    # if 'do_subdomains_resolve' in engine.scans[scan_id]['options'].keys() and engine.scans[scan_id]['options']['do_subdomains_resolve']:
    #     print("passe la")
    #     if 'subdomains_list' in engine.scans[scan_id]['findings'].keys():
    #         if asset in engine.scans[scan_id]['findings']['subdomains_list']:
    #             if subdom not in engine.scans[scan_id]['findings']['subdomains_list'][asset]:
    #                 engine.scans[scan_id]['findings']['subdomains_list'][asset].extend(valid_sudoms)
    #         else:
    #             engine.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms
    #     else:
    #         engine.scans[scan_id]['findings']['subdomains_list'] = {}
    #         engine.scans[scan_id]['findings']['subdomains_list'][asset] = valid_sudoms
    # @todo: mutex on engine.scans[scan_id]['findings']['subdomains_resolve']

    return res


def _subdomain_enum(scan_id, asset):
    res = {}

    # check the asset is a valid domain name
    if not __is_domain(asset):
        return res

    sub_res = sublist3r.main(
        asset,
        1,
        None,
        ports=None,
        silent=True,
        verbose=True,
        enable_bruteforce=False,
        engines=None,
    )

    res.update({asset: sub_res})

    if "subdomains_list" in engine.scans[scan_id]["findings"].keys():
        if asset in engine.scans[scan_id]["findings"]["subdomains_list"]:
            for subdom in sub_res:
                if (
                    subdom
                    not in engine.scans[scan_id]["findings"]["subdomains_list"][asset]
                ):
                    engine.scans[scan_id]["findings"]["subdomains_list"][asset].extend(
                        sub_res
                    )
        else:
            engine.scans[scan_id]["findings"]["subdomains_list"][asset] = list(sub_res)
    else:
        engine.scans[scan_id]["findings"]["subdomains_list"] = {}
        engine.scans[scan_id]["findings"]["subdomains_list"][asset] = list(sub_res)

    if (
        "do_subdomains_resolve" in engine.scans[scan_id]["options"].keys()
        and engine.scans[scan_id]["options"]["do_subdomains_resolve"]
    ):
        res_subdomains = {}
        for s in sub_res:
            data = _dns_resolve_asset(s)
            if len(data) > 0:
                res_subdomains.update({s: data})

        # with engine.scan_lock:
        if "subdomains_resolve" not in engine.scans[scan_id]["findings"].keys():
            engine.scans[scan_id]["findings"]["subdomains_resolve"] = {}
        if asset not in engine.scans[scan_id]["findings"]["subdomains_resolve"].keys():
            engine.scans[scan_id]["findings"]["subdomains_resolve"][asset] = {}
        engine.scans[scan_id]["findings"]["subdomains_resolve"][asset].update(
            res_subdomains
        )

    return res


@app.route("/engines/owl_dns/stop/<scan_id>")
def stop_scan(scan_id):
    # leaving engine because of futures field in status_scan
    res = {"page": "stop"}

    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    status_scan(scan_id)
    if engine.scans[scan_id]["status"] != "SCANNING":
        res.update(
            {
                "status": "error",
                "reason": "scan '{}' is not running (status={})".format(
                    scan_id, engine.scans[scan_id]["status"]
                ),
            }
        )
        return jsonify(res)

    for t in engine.scans[scan_id]["threads"]:
        try:
            t.join()
            engine.scans[scan_id]["threads"].remove(t)
        except Exception:
            pass

    engine.scans[scan_id]["status"] = "STOPPED"
    engine.scans[scan_id]["finished_at"] = int(time.time() * 1000)

    res.update({"status": "success"})
    return jsonify(res)


# Stop all scans
@app.route("/engines/owl_dns/stopscans", methods=["GET"])
def stop():
    res = {"page": "stopscans"}
    for scan_id in engine.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route("/engines/owl_dns/clean")
def clean():
    """Clean all scans."""
    reloadconfig()
    return engine.clean()


@app.route("/engines/owl_dns/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/owl_dns/status/<scan_id>")
def status_scan(scan_id):
    if scan_id not in engine.scans.keys():
        return jsonify(
            {"status": "ERROR", "details": "scan_id '{}' not found".format(scan_id)}
        )

    all_threads_finished = True

    if "threads" in engine.scans[scan_id]:
        for t in engine.scans[scan_id]["threads"]:
            if t.is_alive():
                engine.scans[scan_id]["status"] = "SCANNING"
                all_threads_finished = False
                break
            else:
                # Terminate thread
                t.join()
                engine.scans[scan_id]["threads"].remove(t)

    if "futures" in engine.scans[scan_id]:
        for f in engine.scans[scan_id]["futures"]:
            if not f.done():
                engine.scans[scan_id]["status"] = "SCANNING"
                all_threads_finished = False
                break
            else:
                try:
                    dnstwist_asset, dnstwist_results = f.result()
                    engine.scans[scan_id]["dnstwist"][dnstwist_asset] = dnstwist_results
                except Exception:
                    pass
                engine.scans[scan_id]["futures"].remove(f)

    if (
        "threads" not in engine.scans[scan_id]
        and "futures" not in engine.scans[scan_id]
    ):
        engine.scans[scan_id]["status"] = "STARTED"
        all_threads_finished = False

    try:
        if (
            all_threads_finished
            and len(engine.scans[scan_id]["threads"]) == 0
            and len(engine.scans[scan_id]["futures"]) == 0
        ):
            engine.scans[scan_id]["status"] = "FINISHED"
            engine.scans[scan_id]["finished_at"] = int(time.time() * 1000)
    except Exception:
        pass

    return jsonify({"status": engine.scans[scan_id]["status"]})


@app.route("/engines/owl_dns/fullstatus")
def get_full_status(self):
    """Return engine status with all assets on scans."""
    return _status_owl_dns(True)


@app.route("/engines/owl_dns/status")
def status():
    return _status_owl_dns()


def _status_owl_dns(full_status=False):
    """Get the status of the engine and all its scans."""
    # FIXME ARS-280 this is c/c because of weird use of threadpool and futures field
    res = {"page": "status"}
    engine.scanner["status"] = "READY"
    status_code = 200

    # display info on the scanner
    res.update({"scanner": engine.scanner})

    # display the status of scans performed
    scans = {}
    all_scans = list(engine.scans.keys()).copy()
    for scan in all_scans:
        try:
            engine.status_scan(scan)
            scans.update(
                {
                    scan: {
                        "status": engine.scans[scan]["status"],
                        "options": engine.scans[scan]["options"],
                        "nb_findings": engine.scans[scan]["nb_findings"],
                        "nb_assets": len(engine.scans[scan]["assets"]),
                        "position": engine.scans[scan]["position"],
                        "root_scan_id": engine.scans[scan]["root_scan_id"],
                    }
                }
            )
            if full_status:
                scans[scan].update({"assets": engine.scans[scan]["assets"]})
        except Exception:
            pass
    res.update({"scans": scans})

    if engine._engine_is_busy() is True:
        engine.scanner["status"] = "BUSY"

    conf_file = engine.base_dir + "/" + engine.name + ".json"
    if not os.path.exists(conf_file):
        engine.scanner["status"] = "ERROR"

    res.update({"status": engine.scanner["status"]})
    if engine.scanner["status"] == "ERROR":
        status_code = 500
    return jsonify(res), status_code


def _parse_results(scan_id):
    issues = []
    summary = {}

    # scan = engine.scans[scan_id]
    scan = copy.deepcopy(engine.scans[scan_id])
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    ts = int(time.time() * 1000)

    # dnstwist
    if "dnstwist" in engine.scans[scan_id].keys():
        for asset in engine.scans[scan_id]["dnstwist"].keys():
            try:
                dnstwist_issues = DnsTwist.parse_results(
                    ts, asset, engine.scans[scan_id]["dnstwist"][asset]
                )
            except KeyError:
                app.logger.error("dnstwist: missing result (domain-name)")
                dnstwist_issues = []
            for dnstwist_issue in dnstwist_issues:
                nb_vulns[dnstwist_issue["severity"]] += 1
                issues.append(dnstwist_issue)

    # dns resolve
    if "dns_resolve" in engine.scans[scan_id]["findings"].keys():
        for asset in engine.scans[scan_id]["findings"]["dns_resolve"].keys():
            dns_resolve_str = ""
            dns_records = engine.scans[scan_id]["findings"]["dns_resolve"][asset]
            # print(asset, dns_records)
            # for key, value in sorted(scan['findings']['dns_resolve'].items(), key=lambda x:x[1], reverse=True):
            # for key, value in sorted(engine.scans[scan_id]['findings']['dns_resolve'][asset].items(), key=lambda x:x[1], reverse=True):
            # for value in dns_records:
            #     for record in value:
            #         entry = "Record type '{}': {}".format(record['record_type'], ", ".join(record['values']))
            #         dns_resolve_str = "".join((dns_resolve_str, entry+"\n"))

            for record in dns_records:
                entry = "Record type '{}': {}".format(
                    record["record_type"], ", ".join(record["values"])
                )
                dns_resolve_str = "".join((dns_resolve_str, entry + "\n"))

            dns_resolve_hash = hashlib.sha1(
                dns_resolve_str.encode("utf-8")
            ).hexdigest()[:6]

            nb_vulns["info"] += 1
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": "DNS Resolution entries for '{}' (HASH: {})".format(
                        asset, dns_resolve_hash
                    ),
                    "description": "DNS Resolution entries for '{}':\n\n{}".format(
                        asset, dns_resolve_str
                    ),
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "dns", "resolution"]},
                    "type": "dns_resolve",
                    "raw": dns_records,
                    "timestamp": ts,
                }
            )

    if "seg_dict" in scan["findings"].keys():
        for asset in scan["findings"]["seg_dict"].keys():
            seg_check = scan["findings"]["seg_dict"][asset]
            if len(seg_check) == 0:
                continue
            seg_check_dns_records = scan["findings"]["seg_dict_dns_records"][asset]
            for seg in seg_check:
                seg_provider = list(seg.keys())[0]
                seg_title = (
                    f"{seg[seg_provider]['provider']}/{seg[seg_provider]['product']}"
                )
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": "info",
                        "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "domain"},
                        "title": f"Secure Email Gateway found: {seg_title}",
                        "description": f"{seg}\n",
                        "solution": "n/a",
                        "metadata": {"tags": ["domains", "seg"]},
                        "type": "seg_check",
                        "raw": {"provider": seg, "mx_records": seg_check_dns_records},
                        "timestamp": ts,
                    }
                )

    if "no_seg" in scan["findings"].keys():
        for asset in scan["findings"]["no_seg"].keys():
            seg_check_failed = scan["findings"]["no_seg"][asset]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": "No Secure Email Gateway found",
                    "description": f"{seg_check_failed}\n",
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "no_seg"]},
                    "type": "seg_check",
                    "raw": seg_check_failed,
                    "timestamp": ts,
                }
            )

    if "spf_issues" in scan["findings"]:
        for asset_value in scan["findings"]["spf_issues"]:
            issues_from_spf_check = scan["findings"]["spf_issues"][asset_value][
                "issues"
            ]
            parsed_spf_record = scan["findings"]["spf_issues"][asset_value]["parsed_spf_record"]

            for spf_issue in issues_from_spf_check:
                description = spf_issue.get("description")
                if spf_issue.get("value"):
                    description += f"\n\nThe SPF record is: {spf_issue['value']}"
                if spf_issue.get("extra_info"):
                    description += f"\n\n{spf_issue['extra_info']}"

                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": spf_issue.get("severity", "info"),
                        "confidence": spf_issue.get("confidence", "certain"),
                        "target": {"addr": [asset_value], "protocol": "domain"},
                        "title": spf_issue.get("title"),
                        "description": description,
                        "solution": spf_issue.get("solution"),
                        "metadata": {"tags": ["domains", "spf"]},
                        "type": "spf_check",
                        "raw": {
                            "description": spf_issue.get("description"),
                            "solution": spf_issue.get("solution"),
                            "parsed": parsed_spf_record,
                            "value": spf_issue.get("value"),
                            "extra_info": spf_issue.get("extra_info"),
                        },
                        "timestamp": ts,
                    }
                )

    if "dkim_dict" in scan["findings"].keys():
        for asset in scan["findings"]["dkim_dict"].keys():
            dkim_check = scan["findings"]["dkim_dict"][asset]
            dkim_check_dns_records = scan["findings"]["dkim_dict_dns_records"][asset]
            dkim_hash = hashlib.sha1(
                str(dkim_check_dns_records).encode("utf-8")
            ).hexdigest()[:6]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": "DKIM check for '{}' (HASH: {})".format(asset, dkim_hash),
                    "description": "DKIM check for '{}':\n\n{}".format(
                        asset, str(dkim_check)
                    ),
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "dkim"]},
                    "type": "dkim_check",
                    "raw": scan["findings"]["dkim_dict"][asset],
                    "timestamp": ts,
                }
            )

    if "dmarc_dict" in scan["findings"].keys():
        for asset in scan["findings"]["dmarc_dict"].keys():
            dmarc_check = scan["findings"]["dmarc_dict"][asset]
            dmarc_check_dns_records = scan["findings"]["dmarc_dict_dns_records"][asset]
            for c in dmarc_check:
                h = str(c) + str(dmarc_check_dns_records)
                dmarc_hash = hashlib.sha1(h.encode("utf-8")).hexdigest()[:6]
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": dmarc_check[c],
                        "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "domain"},
                        "title": "DMARC for '{}' (HASH: {})".format(asset, dmarc_hash),
                        "description": "{}\n".format(c),
                        "solution": "n/a",
                        "metadata": {"tags": ["domains", "dmarc"]},
                        "type": "dmarc_check",
                        "raw": scan["findings"]["dmarc_dict"][asset],
                        "timestamp": ts,
                    }
                )

    # subdomain resolve
    if "subdomains_resolve" in scan["findings"].keys():
        for asset in scan["findings"]["subdomains_resolve"].keys():
            for subdom in scan["findings"]["subdomains_resolve"][asset].keys():
                subdom_resolve_str = ""
                for record in scan["findings"]["subdomains_resolve"][asset][subdom]:
                    entry = "Record type '{}': {}".format(
                        record["record_type"], ", ".join(record["values"])
                    )
                    subdom_resolve_str = "".join((subdom_resolve_str, entry + "\n"))

                subdom_resolve_hash = hashlib.sha1(
                    subdom_resolve_str.encode("utf-8")
                ).hexdigest()[:6]

                raw_record = {
                    "dns_record": scan["findings"]["subdomains_resolve"][asset][subdom],
                    "subdomain": subdom,
                }

                nb_vulns["info"] += 1
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": "info",
                        "confidence": "certain",
                        "target": {
                            # "addr": [asset, subdom],
                            "addr": [asset],
                            "protocol": "domain",
                        },
                        "title": "DNS Resolution entries for '{}' (HASH: {})".format(
                            subdom, subdom_resolve_hash
                        ),
                        "description": "DNS Resolution entries for '{}':\n\n{}".format(
                            subdom, subdom_resolve_str
                        ),
                        "solution": "n/a",
                        "metadata": {"tags": ["dns", "resolution", "subdomain"]},
                        "type": "subdomains_resolve",
                        "raw": raw_record,
                        "timestamp": ts,
                    }
                )

    # reverse dns
    if "reverse_dns" in scan["findings"].keys():
        for asset in scan["findings"]["reverse_dns"].keys():
            nb_vulns["info"] += 1
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": "IP '{}' points to domain name '{}'".format(
                        asset, ", ".join(scan["findings"]["reverse_dns"][asset])
                    ),
                    "description": "IP '{}' points to domain name '{}'".format(
                        asset, ", ".join(scan["findings"]["reverse_dns"][asset])
                    ),
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "dns", "reverse", "lookup"]},
                    "type": "reverse_dns",
                    "raw": scan["findings"]["reverse_dns"][asset],
                    "timestamp": ts,
                }
            )

    # reverse whois lookup
    if "reverse_whois" in scan["findings"].keys():
        for asset in scan["findings"]["reverse_whois"].keys():
            nb_vulns["info"] += 1
            domains_str = ""
            reverse_whois_domains = scan["findings"]["reverse_whois"][asset]["domains"]
            for domain in reverse_whois_domains:
                domains_str = "".join((domains_str, domain + "\n"))
            domains_hash = hashlib.sha1(domains_str.encode("utf-8")).hexdigest()[:6]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Reverse Whois lookup on '{asset}' ({domains_hash})",
                    "description": f"Reverse Whois lookup on '{asset}' ({domains_hash})\nFound domains: {len(reverse_whois_domains)}",
                    "solution": "n/a",
                    "metadata": {
                        "tags": ["domains", "dns", "reverse", "lookup", "whois"]
                    },
                    "type": "reverse_whois_data",
                    "raw": scan["findings"]["reverse_whois"][asset],
                    "timestamp": ts,
                }
            )

    # is IP behind a CDN ?
    if "cdn_check" in scan["findings"].keys():
        for asset in scan["findings"]["cdn_check"].keys():
            nb_vulns["info"] += 1
            provider = scan["findings"]["cdn_check"][asset]["provider"]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Behind CDN: '{provider}'",
                    "description": f"Behind CDN: '{provider}'",
                    "solution": "n/a",
                    "metadata": {"tags": ["cdn", provider]},
                    "type": "cdn_check",
                    "raw": scan["findings"]["cdn_check"][asset],
                    "timestamp": ts,
                }
            )

    # is IP behind a WAF ?
    if "waf_check" in scan["findings"].keys():
        for asset in scan["findings"]["waf_check"].keys():
            nb_vulns["info"] += 1
            provider = scan["findings"]["waf_check"][asset]["provider"]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Behind WAF: '{provider}'",
                    "description": f"Behind WAF: '{provider}'",
                    "solution": "n/a",
                    "metadata": {"tags": ["waf", provider]},
                    "type": "waf_check",
                    "raw": scan["findings"]["waf_check"][asset],
                    "timestamp": ts,
                }
            )

    # is IP supported by a public Cloud ?
    if "cloud_check" in scan["findings"].keys():
        for asset in scan["findings"]["cloud_check"].keys():
            nb_vulns["info"] += 1
            provider = scan["findings"]["cloud_check"][asset]["provider"]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Behind Cloud Provider: '{provider}'",
                    "description": f"Behind Cloud Provider: '{provider}'",
                    "solution": "n/a",
                    "metadata": {"tags": ["cloud", provider]},
                    "type": "cloud_check",
                    "raw": scan["findings"]["cloud_check"][asset],
                    "timestamp": ts,
                }
            )

    # is IP supported by a SaaS service ?
    if "saas_check" in scan["findings"].keys():
        for asset in scan["findings"]["saas_check"].keys():
            nb_vulns["info"] += 1
            provider = scan["findings"]["saas_check"][asset]["provider"]
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Behind SaaS Provider: '{provider}'",
                    "description": f"Behind SaaS Provider: '{provider}'",
                    "solution": "n/a",
                    "metadata": {"tags": ["saas", provider]},
                    "type": "saas_check",
                    "raw": scan["findings"]["saas_check"][asset],
                    "timestamp": ts,
                }
            )

    # subdomain list

    # bad messages replied by Sublist3r
    bad_str = [
        "Go to http://PTRarchive.com for best",
        "Use http://PTRarchive.com, the engine",
        "Sublist3r recommends",
        "API count exceeded",
        "Too Many Requests",
        "error invalid host",
        "<",
        ">",
    ]
    if "subdomains_list" in scan["findings"].keys():
        for asset in scan["findings"]["subdomains_list"].keys():
            subdomains_str = ""
            subdomains_list = sorted(set(scan["findings"]["subdomains_list"][asset]))
            subdomains_list_clean = []

            # Associate these findings to the asset or create new assets
            create_new_assets = False
            if (
                "subdomain_as_new_asset" in scan["options"].keys()
                and scan["options"]["subdomain_as_new_asset"]
            ):
                create_new_assets = True

            for subdomain in subdomains_list:
                subdomain = subdomain.strip().lower()
                if (
                    any(x in subdomain for x in bad_str)
                    or subdomain.replace(" ", "") == ""
                ):
                    continue
                s = subdomain.replace("From http://PTRarchive.com: ", "")
                subdomains_list_clean.append(s)
                subdomains_str = "".join((subdomains_str, s + "\n"))

                # New issue when a subdomain is found
                nb_vulns["info"] += 1
                if create_new_assets:
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "info",
                            "confidence": "certain",
                            "target": {"addr": [s], "protocol": "domain"},
                            "title": "Subdomain found: {}".format(s),
                            "description": "Subdomain found:\n\n{}".format(s),
                            "solution": "n/a",
                            "metadata": {"tags": ["domains", "subdomain"]},
                            "type": "subdomain",
                            "raw": s,
                            "timestamp": ts,
                        }
                    )
                else:
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "info",
                            "confidence": "certain",
                            "target": {"addr": [asset], "protocol": "domain"},
                            "title": "Subdomain found: {}".format(s),
                            "description": "Subdomain found:\n\n{}".format(s),
                            "solution": "n/a",
                            "metadata": {"tags": ["domains", "subdomain"]},
                            "type": "subdomain",
                            "raw": s,
                            "timestamp": ts,
                        }
                    )

            # New issue when on the domain list
            subdomains_hash = hashlib.sha1(subdomains_str.encode("utf-8")).hexdigest()[
                :6
            ]
            if len(subdomains_list_clean) == 0:
                subdomains_list_clean = []

            nb_vulns["info"] += 1
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": "List of subdomains for '{}' ({} found, HASH: {})".format(
                        asset, len(subdomains_list_clean), subdomains_hash
                    ),
                    "description": "Subdomain list for '{}': \n\n{}".format(
                        asset, subdomains_str
                    ),
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "subdomains"]},
                    "type": "subdomains_enum",
                    "raw": subdomains_list_clean,
                    "timestamp": ts,
                }
            )

    # whois info for domain
    if "whois" in scan["findings"].keys():
        for asset in scan["findings"]["whois"].keys():
            nb_vulns["info"] += 1
            # check errors
            if "errors" in scan["findings"]["whois"][asset].keys():
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": "info",
                        "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "domain"},
                        "title": "[Whois] No match for '{}'".format(asset),
                        "description": "No Whois data available for domain '{}'. Note that Whois is available for registered domains only (not sub-domains): \n{}".format(
                            asset, scan["findings"]["whois"][asset]["errors"]
                        ),
                        "solution": "n/a",
                        "metadata": {"tags": ["whois"]},
                        "type": "whois_domain_error",
                        "raw": scan["findings"]["whois"][asset]["errors"],
                        "timestamp": ts,
                    }
                )
            else:
                whois_hash = hashlib.sha1(
                    str(scan["findings"]["whois"][asset]["text"]).encode("utf-8")
                ).hexdigest()[:6]
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": "info",
                        "confidence": "certain",
                        "target": {"addr": [asset], "protocol": "domain"},
                        "title": "Whois info for '{}' (HASH: {})".format(
                            asset, whois_hash
                        ),
                        "description": "Whois Info (raw): \n\n{}".format(
                            str(scan["findings"]["whois"][asset]["text"])
                        ),
                        "solution": "n/a",
                        "metadata": {
                            "tags": ["whois", scan["findings"]["whois"][asset]["type"]]
                        },
                        "type": f"whois_{scan['findings']['whois'][asset]['type']}_fullinfo",
                        "raw": scan["findings"]["whois"][asset]["raw"],
                        "timestamp": ts,
                    }
                )

        # advanced whois info
        if (
            "do_advanced_whois" in scan["options"].keys()
            and scan["options"]["do_advanced_whois"]
        ):
            for asset in scan["findings"]["whois"].keys():
                if "errors" in scan["findings"]["whois"][asset].keys():
                    continue

                issue = {
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "solution": "n/a",
                    "metadata": {"tags": ["whois"]},
                    "timestamp": ts,
                }

                # status
                nb_vulns["info"] += 1
                whois_statuses = ",\n".join(
                    scan["findings"]["whois"][asset]["raw"]["status"]
                )
                dom_status = copy.deepcopy(issue)
                dom_status.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_domain_status",
                        "title": "[Whois] '{}' domain has status '{}'".format(
                            asset, scan["findings"]["whois"][asset]["raw"]["status"][0]
                        ),
                        "description": "[Whois] '{}' domain has status '{}'".format(
                            asset, whois_statuses
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"]["status"],
                    }
                )
                issues.append(dom_status)

                # registrar
                nb_vulns["info"] += 1
                whois_reginfo = "Name: {}\n".format(
                    scan["findings"]["whois"][asset]["raw"]["registrar"]
                )
                whois_reginfo += "ID: {}\n".format(
                    scan["findings"]["whois"][asset]["raw"]["registrar_id"]
                )
                whois_reginfo += "URL(s): {}\n".format(
                    ", ".join(scan["findings"]["whois"][asset]["raw"]["registrar_url"])
                )
                dom_registrar = copy.deepcopy(issue)
                dom_registrar.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_registrar",
                        "title": "[Whois] '{}' domain registrar is '{}'".format(
                            asset, scan["findings"]["whois"][asset]["raw"]["registrar"]
                        ),
                        "description": "[Whois] '{}' domain registrar is '{}': \n{}".format(
                            asset,
                            scan["findings"]["whois"][asset]["raw"]["registrar"],
                            whois_reginfo,
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"]["registrar"],
                    }
                )
                issues.append(dom_registrar)

                # emails
                if (
                    "emails" in scan["findings"]["whois"][asset]["raw"].keys()
                    and scan["findings"]["whois"][asset]["raw"]["emails"]
                ):
                    nb_vulns["info"] += 1
                    dom_emails = copy.deepcopy(issue)
                    dom_emails.update(
                        {
                            "issue_id": len(issues) + 1,
                            "type": "whois_emails",
                            "title": "[Whois] '{}' domain contact emails are set.".format(
                                asset
                            ),
                            "description": "[Whois] '{}' domain contact emails are:\n'{}'".format(
                                asset,
                                ", ".join(
                                    scan["findings"]["whois"][asset]["raw"]["emails"]
                                ),
                            ),
                            "raw": scan["findings"]["whois"][asset]["raw"]["emails"],
                        }
                    )
                    issues.append(dom_emails)

                # nameservers
                nb_vulns["info"] += 1
                dom_nameservers = copy.deepcopy(issue)
                dom_nameservers.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_nameservers",
                        "title": "[Whois] '{}' domain nameservers are set.".format(
                            asset
                        ),
                        "description": "[Whois] '{}' domain nameservers are:\n{}".format(
                            asset,
                            ",\n".join(
                                scan["findings"]["whois"][asset]["raw"]["name_servers"]
                            ),
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"]["name_servers"],
                    }
                )
                issues.append(dom_nameservers)

                # updated_date
                nb_vulns["info"] += 1
                update_dates = [
                    d.date().isoformat()
                    for d in scan["findings"]["whois"][asset]["raw"]["updated_date"]
                ]
                dom_updated_dates = copy.deepcopy(issue)
                dom_updated_dates.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_update_dates",
                        "title": "[Whois] '{}' domain was lastly updated the '{}'".format(
                            asset,
                            max(scan["findings"]["whois"][asset]["raw"]["updated_date"])
                            .date()
                            .isoformat(),
                        ),
                        "description": "[Whois] '{}' domain was updated at the following dates: \n\n{}".format(
                            asset, ", ".join(update_dates)
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"]["updated_date"],
                    }
                )
                issues.append(dom_updated_dates)

                # creation_date
                nb_vulns["info"] += 1
                dom_created_dates = copy.deepcopy(issue)
                dom_created_dates.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_creation_dates",
                        "title": "[Whois] '{}' domain was lastly created the '{}'".format(
                            asset,
                            scan["findings"]["whois"][asset]["raw"]["creation_date"]
                            .date()
                            .isoformat(),
                        ),
                        "description": "[Whois] '{}' domain was created at the following dates: \n\n{}".format(
                            asset,
                            scan["findings"]["whois"][asset]["raw"]["creation_date"],
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"]["creation_date"],
                    }
                )
                issues.append(dom_created_dates)

                # expiry date
                nb_vulns["info"] += 1
                dom_expiration_date = copy.deepcopy(issue)
                dom_expiration_date.update(
                    {
                        "issue_id": len(issues) + 1,
                        "type": "whois_expiration_dates",
                        "title": "[Whois] '{}' domain is registred until '{}'".format(
                            asset,
                            scan["findings"]["whois"][asset]["raw"]["expiration_date"]
                            .date()
                            .isoformat(),
                        ),
                        "description": "[Whois] '{}' domain is registred until '{}'".format(
                            asset,
                            scan["findings"]["whois"][asset]["raw"]["expiration_date"]
                            .date()
                            .isoformat(),
                        ),
                        "raw": scan["findings"]["whois"][asset]["raw"][
                            "expiration_date"
                        ],
                    }
                )
                issues.append(dom_expiration_date)

                # Raise alarms at 6 months (low), 3 months (medium), 2 weeks (high) or when expired (high)
                exp_date = scan["findings"]["whois"][asset]["raw"]["expiration_date"]
                six_month_later = datetime.datetime.now() + datetime.timedelta(
                    days=365 / 2
                )
                three_month_later = datetime.datetime.now() + datetime.timedelta(
                    days=90
                )
                two_weeks_later = datetime.datetime.now() + datetime.timedelta(days=15)

                if exp_date < datetime.datetime.now():
                    nb_vulns["high"] += 1
                    dom_expiration_date_passed = copy.deepcopy(issue)
                    dom_expiration_date_passed.update(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "high",
                            "type": "whois_expiration_dates",
                            "title": "[Whois] '{}' domain is expired since '{}'".format(
                                asset, exp_date.date().isoformat()
                            ),
                            "description": "[Whois] '{}' domain is expired since '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                                asset,
                                exp_date.date().isoformat(),
                                ", ".join(exp_date.date().isoformat()),
                            ),
                            "raw": scan["findings"]["whois"][asset]["raw"][
                                "expiration_date"
                            ],
                            "solution": "Renew the domain",
                        }
                    )
                    issues.append(dom_expiration_date_passed)
                elif exp_date < two_weeks_later:
                    nb_vulns["high"] += 1
                    dom_expiration_date_2w = copy.deepcopy(issue)
                    dom_expiration_date_2w.update(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "high",
                            "type": "whois_expiration_dates",
                            "title": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)".format(
                                asset, exp_date.date().isoformat()
                            ),
                            "description": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                                asset,
                                exp_date.date().isoformat(),
                                ", ".join(exp_date.date().isoformat()),
                            ),
                            "raw": scan["findings"]["whois"][asset]["raw"][
                                "expiration_date"
                            ],
                            "solution": "Renew the domain",
                        }
                    )
                    issues.append(dom_expiration_date_2w)
                elif exp_date < three_month_later:
                    nb_vulns["medium"] += 1
                    dom_expiration_date_3m = copy.deepcopy(issue)
                    dom_expiration_date_3m.update(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "medium",
                            "type": "whois_expiration_dates",
                            "title": "[Whois] '{}' domain is registred until '{}' (less than 3 months)".format(
                                asset, exp_date.date().isoformat()
                            ),
                            "description": "[Whois] '{}' domain is registred until '{}' (less than 3 months)\n\nAll dates in record: {}".format(
                                asset,
                                exp_date.date().isoformat(),
                                ", ".join(exp_date.date().isoformat()),
                            ),
                            "raw": scan["findings"]["whois"][asset]["raw"][
                                "expiration_date"
                            ],
                            "solution": "Renew the domain",
                        }
                    )
                    issues.append(dom_expiration_date_3m)
                elif exp_date < six_month_later:
                    nb_vulns["low"] += 1
                    dom_expiration_date_6m = copy.deepcopy(issue)
                    dom_expiration_date_6m.update(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": "low",
                            "type": "whois_expiration_dates",
                            "title": "[Whois] '{}' domain is registred until '{}' (less than 6 months)".format(
                                asset, exp_date.date().isoformat()
                            ),
                            "description": "[Whois] '{}' domain is registred until '{}' (less than 6 months)\n\nAll dates in record: {}".format(
                                asset,
                                exp_date.date().isoformat(),
                                ", ".join(exp_date.date().isoformat()),
                            ),
                            "raw": scan["findings"]["whois"][asset]["raw"][
                                "expiration_date"
                            ],
                            "solution": "Renew the domain",
                        }
                    )
                    issues.append(dom_expiration_date_6m)

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "owl_dns",
        "engine_version": engine.scanner["version"],
    }

    return issues, summary


@app.route("/engines/owl_dns/getfindings/<scan_id>")
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}
    if not scan_id.isdecimal():
        return jsonify(
            {"status": "error", "reason": "scan_id must be numeric digits only"}
        )

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    # check if the scan is finished
    # status()
    status_scan(scan_id)
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update(
            {
                "status": "error",
                "reason": f"scan_id '{scan_id}' not finished (status={engine.scans[scan_id]['status']})",
            }
        )
        return jsonify(res)

    issues, summary = _parse_results(scan_id)
    scan = {"scan_id": scan_id}

    # Store the findings in a file
    with open(f"{BASE_DIR}/results/owl_dns_{scan_id}.json", "w") as report_file:
        json.dump(
            {"scan": scan, "summary": summary, "issues": issues},
            report_file,
            default=_json_serial,
        )

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update(
        {"scan": scan_id, "summary": summary, "issues": issues, "status": "success"}
    )
    return jsonify(res)


@app.route("/engines/owl_dns/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


@app.route("/engines/owl_dns/test")
def test():
    """Return test page."""
    return engine.test()


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    return engine.page_not_found()


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR + "/results"):
        os.makedirs(BASE_DIR + "/results")
    _loadconfig()


if __name__ == "__main__":
    if sys.platform == "darwin":
        os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"

    parser = optparse.OptionParser()
    parser.add_option(
        "-H",
        "--host",
        help="Hostname of the Flask app [default %s]" % APP_HOST,
        default=APP_HOST,
    )
    parser.add_option(
        "-P",
        "--port",
        help="Port for the Flask app [default %s]" % APP_PORT,
        default=APP_PORT,
    )
    parser.add_option(
        "-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP
    )

    options, _ = parser.parse_args()
    app.run(
        debug=options.debug, host=options.host, port=int(options.port), threaded=True
    )
