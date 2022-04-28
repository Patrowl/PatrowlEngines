#!/usr/bin/python3
# -*- coding: utf-8 -*-

import xml.etree.cElementTree as ET
import re
import hashlib


def parse_report(report_filename, nessus_prefix, resolvefqdn=False):
    """Parse a Nessus report file."""
    summary = {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
        "new": 0, "total": 0
    }
    level_to_value = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    value_to_level = {v: k for k, v in level_to_value.items()}

    data = list()
    try:
        dom = ET.parse(open(report_filename, "r"))
        root = dom.getroot()
    except Exception:
        print("Unable to open and parse report file.")
        return False

    try:
        for block in root:
            if block.tag == 'Report':
                for report_host in block:
                    asset = dict()
                    asset['name'] = report_host.attrib['name']
                    for report_item in report_host:
                        if report_item.tag == 'HostProperties':
                            for tag in report_item:
                                asset[tag.attrib['name']] = tag.text
                        asset_addrs = [asset.get('name')]
                        if 'host-ip' in asset.keys() and asset['host-ip'] not in asset_addrs:
                            asset_addrs.append(asset['host-ip'])
                        if resolvefqdn is True and 'host-fqdn' in asset.keys() and asset['host-fqdn'] not in asset_addrs:
                            asset_addrs.append(asset['host-fqdn'])
                        if 'pluginName' in report_item.attrib:
                            summary['total'] += 1
                            service = ""
                            if report_item.attrib['port'] != "0":
                                service = "{}/{}".format(report_item.attrib['protocol'], report_item.attrib['port'])
                                title = "{}: {}".format(service, report_item.attrib['pluginName'])
                            else:
                                title = report_item.attrib['pluginName']
                            finding = {
                                "target": {
                                    "addr": asset_addrs,
                                    "port_type": report_item.attrib['protocol'],
                                    "port_id": report_item.attrib['port']
                                },
                                "metadata": {
                                    "risk": {
                                        "cvss_base_score": "0.0"
                                    },
                                    "vuln_refs": {},
                                    "links": list(),
                                    "tags": [
                                        "nessus",
                                        report_item.attrib['pluginFamily'].lower(),
                                        report_item.find('plugin_type').text,
                                        "pluginid_"+str(report_item.attrib['pluginID']),
                                    ]
                                },
                                "title": title,
                                "type": report_item.attrib['pluginFamily'].lower().replace(" ", "_"),
                                "confidence": "certain",
                                "severity": "info",
                                "description": "n/a",
                                "solution": "n/a",
                                "raw": None
                            }

                            finding['severity'] = value_to_level.get(int(report_item.attrib['severity']), 'info')
                            summary[finding['severity']] += 1

                            for param in report_item:
                                if param.tag == 'vuln_publication_date':
                                    finding['metadata']['vuln_publication_date'] = param.text

                                if param.tag == 'solution':
                                    finding['solution'] = "{}: {}".format(service, param.text)
                                if param.tag == 'description':
                                    finding['description'] = "Service: {}\n{}".format(service, param.text)
                                # if param.tag == 'synopsis':
                                #     finding['title'] = "{}: {}".format(service, param.text)

                                if param.tag == 'cvss_vector':
                                    finding['metadata']['risk']['cvss_vector'] = param.text
                                if param.tag == 'cvss_base_score':
                                    finding['metadata']['risk']['cvss_base_score'] = param.text

                                if param.tag == 'cvss_temporal_vector':
                                    finding['metadata']['risk']['cvss_temporal_vector'] = param.text
                                if param.tag == 'cvss_temporal_score':
                                    finding['metadata']['risk']['cvss_temporal_score'] = param.text

                                if param.tag == 'cvss3_vector':
                                    finding['metadata']['risk']['cvss3_vector'] = param.text
                                if param.tag == 'cvss3_base_score':
                                    finding['metadata']['risk']['cvss3_base_score'] = param.text

                                if param.tag == 'cvss3_temporal_vector':
                                    finding['metadata']['risk']['cvss3_temporal_vector'] = param.text
                                if param.tag == 'cvss3_temporal_score':
                                    finding['metadata']['risk']['cvss3_temporal_score'] = param.text

                                if param.tag == 'exploit_available':
                                    finding['metadata']['risk']['exploit_available'] = param.text
                                if param.tag == 'exploitability_ease':
                                    finding['metadata']['risk']['exploitability_ease'] = param.text
                                if param.tag == 'exploited_by_nessus':
                                    finding['metadata']['risk']['exploited_by_nessus'] = param.text
                                if param.tag == 'patch_publication_date':
                                    finding['metadata']['risk']['patch_publication_date'] = param.text

                                if param.tag == 'cwe':
                                    finding['metadata']['vuln_refs']['CWE'] = param.text.split(', ')
                                if param.tag == 'cpe':
                                    finding['metadata']['vuln_refs']['CPE'] = param.text.split(', ')
                                if param.tag == 'cve':
                                    finding['metadata']['vuln_refs']['CVE'] = param.text.split(', ')
                                if param.tag == 'cert':
                                    finding['metadata']['vuln_refs']['CERT'] = param.text.split(', ')
                                if param.tag == 'bid':
                                    finding['metadata']['vuln_refs']['BID'] = param.text.split(', ')
                                if param.tag == 'xref':
                                    finding['metadata']['vuln_refs'][param.text.split(':')[0].upper()] = param.text.split(':')[1]
                                if param.tag == 'see_also':
                                    for link in param.text.split('\n'):
                                        finding['metadata']['links'].append(link)

                                if param.tag == 'plugin_output':
                                    finding['raw'] = param.text
                                    plugin_output = str(re.sub('Scan Start Date:.*\n', '\n', str(param.text)))
                                    finding['description'] = finding['description'] + "\n\nScanner output:\n\n" + plugin_output

                            #finding_hash = hashlib.sha1(str(finding['description']).encode("utf-8")).hexdigest()[:6]
                            #finding['title'] += " ({})".format(finding_hash)
                            data.append(finding)

    except Exception as e:
        print("Error parsing nessus report file '{}'".format(report_filename))
        print(e)
        return False
    return summary, data
