#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
PastebinMonitor Tests
'''

# Standard library imports
from __future__ import absolute_import
from __future__ import print_function
from json import dumps
import sys

# Third party library imports
from requests import Session

SESSION = Session()
BASE_URL = "http://192.168.184.99:5030/engines/pastebin_monitor"

print("TEST CASE: test_startscan_pastebin_monitor")

POST_DATA = {
    "assets": [
        {"id": 1, "value": "patrowl.io", "criticity": "low", "datatype": "domain"},
        {"id": 2, "value": "patrowl-test.io", "criticity": "high", "datatype": "domain"}
    ],
    "options": '',
    "scan_id": 666
}

_ = SESSION.post(url="{}/startscan".format(BASE_URL),
                 data=dumps(POST_DATA),
                 headers={"Content-type": "application/json", "Accept": "application/json"})
REQ = SESSION.get(url="{}/status/666".format(BASE_URL))
print(REQ.json())
REQ = SESSION.get(url="{}/getfindings/666".format(BASE_URL))
print(REQ.json())
REQ = SESSION.get(url="{}/getreport/666".format(BASE_URL))
print(REQ.json())

sys.exit(0)
