#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Censys Tests
"""

# Standard library imports
from __future__ import absolute_import
from __future__ import print_function
from json import dumps

# Third party library imports
from requests import Session

SESSION = Session()
BASE_URL = "http://127.0.0.1:5010/engines/censys"

print("TEST CASE: test_startscan_censys")

POST_DATA = {
    "assets": ["*.patrowl.io"],
    "options" : {
        "do_scan_valid": True,
        "ignore_changed_certificate": True,
        "changed_certificate_port_test": [443, 465, 636, 993, 995, 8443, 9443],
        "do_scan_trusted": True,
        "verbose": True,
        "do_scan_ca_trusted": True,
        "do_scan_self_signed": True,
        "keyword": ['parsed.subject.organization: "PatrOwl"'],
        "trusted_self_signed": [],
        "trusted_host":
            [
                "www.patrowl.io",
                "blog.patrowl.io"
            ],
        "trusted_ca_certificate":
            [],
    },
    "scan_id": 666
}

_ = SESSION.post(url="{}/startscan".format(BASE_URL),
                 data=dumps(POST_DATA),
                 headers={"Content-type": "application/json", "Accept": "application/json"})
REQ = SESSION.get(url="{}/status/666".format(BASE_URL))
print(REQ.json())

exit(0)
