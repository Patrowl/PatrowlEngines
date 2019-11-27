#!/usr/bin/python3
# -*- coding: utf-8 -*-

def parse_report(report_filename):

    summary = {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
        "missing": 0, "new": 0, "total": 0
    }

    try:
        import cElementTree as ET
    except ImportError:
        try:
            # Python 2.5 need to import a different module
            import xml.etree.cElementTree as ET
        except ImportError:
            Event.objects.create(message="[EngineTasks/importfindings_task()] Unable to import xml parser.", type="ERROR", severity="ERROR")
            return False

    # parse nessus file
    data = list()
    try:
        dom = ET.parse(open(report_filename, "r"))
        root = dom.getroot()
    except Exception as e:
        Event.objects.create(message="[EngineTasks/importfindings_task()] Unable to open and parse report file.", description="{}".format(e.message),
                     type="ERROR", severity="ERROR")
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
                        if not net.is_valid_ip(asset.get('host-ip', asset.get('name'))):
                            Event.objects.create(
                                message="[EngineTasks/importfindings_task()] finding not added.",
                                type="DEBUG", severity="DEBUG",
                                description="No ip address for asset {} found".format(asset.get('name'))
                            )
                            summary['missing'] += 1
                            continue
                        if 'pluginName' in report_item.attrib:
                            summary['total'] += 1
                            finding = {
                                "target": {
                                    "addr": [asset.get('host-ip', asset.get('name'))]
                                },
                                "metadata": {
                                    "risk": {
                                        "cvss_base_score": "0.0"
                                    },
                                    "vuln_refs": {},
                                    "links": list(),
                                    "tags": ["nessus"]
                                },
                                "title": report_item.attrib['pluginName'],
                                "type": "nessus_manual_import",
                                "confidence": "3",
                                "severity": "info",
                                "description": "n/a",
                                "solution": "n/a",
                                "raw": None
                            }
                            if int(report_item.attrib['severity']) < min_level:
                                # if below min level descard finding
                                summary['missing'] += 1
                                continue
                            finding['severity'] = value_to_level.get(int(report_item.attrib['severity']), 'info')
                            summary[finding['severity']] += 1

                            for param in report_item:
                                if param.tag == 'vuln_publication_date':
                                    finding['metadata']['vuln_publication_date'] = param.text

                                if param.tag == 'solution':
                                    finding['solution'] = param.text
                                if param.tag == 'description':
                                    finding['description'] = param.text

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

                                if param.tag == 'cve':
                                    finding['metadata']['vuln_refs']['CVE'] = param.text.split(', ')
                                if param.tag == 'bid':
                                    finding['metadata']['vuln_refs']['BID'] = param.text.split(', ')
                                if param.tag == 'xref':
                                    finding['metadata']['vuln_refs'][param.text.split(':')[0].upper()] = param.text.split(':')[1]
                                if param.tag == 'see_also':
                                    for link in param.text.split('\n'):
                                        finding['metadata']['links'].append(link)

                                if param.tag == 'plugin_output':
                                    finding['raw'] = param.text
                            data.append(finding)
