#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import subprocess
import os
import json
import hashlib
from .common import json_validator

DNSTWIST_TIMEOUT = 600
DNSTWIST_NB_THREADS = 5


class dnstwist:
    identifier = 'dnstwist'

    def __init__(self, path):
        self.loadconfig(path)

    def loadconfig(self, path):
        try:
            sys.path.append(path)
            globals()['dnstwist'] = __import__('dnstwist')
            print("[+] INFO - dnstwist module sucessfully loaded.")
            return True
        except Exception:
            print("[+] ERROR - Not able to load dnstwist module.")
            return False

    def search_subdomains(scan_id, domain, tld=False, ssdeep=False, geoip=False, mxcheck=False, whois=False, banners=False, timeout=DNSTWIST_TIMEOUT, nb_threads=DNSTWIST_NB_THREADS):
        cmd = "{} -r -f json -t {}".format(globals()['dnstwist'].__file__, nb_threads)
        if tld and os.path.exists(tld):
            cmd += " --tld {}".format(tld)
        if ssdeep:
            cmd += " -s"
        if geoip:
            cmd += " -g"
        if mxcheck:
            cmd += " -m"
        if whois:
            cmd += " -w"
        if banners:
            cmd += " -b"
        cmd += " {}".format(domain)

        outs = b'[{}]'
        try:
            outs = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print("[+] ERROR - Timeout reached ({}s) for cmd: {}".format(timeout, cmd))

        if json_validator(outs):
            return domain, json.loads(outs)
        else:
            return domain, {}

    def parse_results(ts, asset, domains):
        issues = []
        for domain in domains:
            if domain['fuzzer'] == 'original*':
                continue
            result_str = ""
            if 'dns-a' in domain.keys():
                result_str += "Resolved IPv4 (A): \n{}\n\n".format("\n".join(domain['dns-a']))
            if 'dns-aaaa' in domain.keys():
                result_str += "Resolved IPv6 (aaaa): \n{}\n\n".format("\n".join(domain['dns-aaaa']))
            if 'dns-mx' in domain.keys():
                result_str += "Resolved MX: \n{}\n\n".format("\n".join(domain['dns-mx']))
            if 'dns-ns' in domain.keys():
                result_str += "Resolving Nameservers: \n{}\n\n".format("\n".join(domain['dns-ns']))
            if 'geoip-country' in domain.keys():
                result_str += "GeoIP location: {}\n\n".format(domain['geoip-country'])
            if 'fuzzer' in domain.keys():
                result_str += "Fuzzer source: {}\n\n".format(domain['fuzzer'])
            if 'whois-created' in domain.keys() and domain['whois-created'] != "None":
                result_str += "Whois creation date: {}\n".format(domain['whois-created'])
            if 'whois-updated' in domain.keys() and domain['whois-updated'] != "None":
                result_str += "Whois last update: {}\n".format(domain['whois-updated'])

            result_hash = hashlib.sha1(result_str.encode("utf-8")).hexdigest()[:6]

            issues.append({
                "issue_id": len(issues)+1,
                "severity": "low", 
                "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "domain"
                },
                "title": "Suspicious domain found: {} (HASH: {})".format(
                    domain['domain-name'], result_hash),
                "description": "DNS information for '{}':\n\n{}".format(
                    domain['domain-name'], result_str),
                "solution": "Check suspiciousness of domain '{}'".format(
                    domain['domain-name']
                ),
                "metadata": {
                    "tags": ["domains", "dns", "fraudulent", "typosquatting"]
                },
                "type": "typosquated_domain",
                "raw": domain,
                "timestamp": ts
            })
        return issues
