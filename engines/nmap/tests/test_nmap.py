#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
NMAP Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5001/engines/nmap"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="nmap", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()

# TODO: Fix "No PID found" error
# def test_nmap_vulners():
#     """Custom tests."""
#     PET.custom_test(
#         test_name="nmap_vulners",
#         assets=[{
#             "id": "1",
#             "value": "patrowl.io",
#             "criticity": "low",
#             "datatype": "domain"
#         }],
#         scan_policy={
#             "no_ping": 0,
#             "ports": [
#                 "80",
#                 "22",
#                 "443",
#                 "56",
#                 "25"
#             ],
#             "detect_service_version": 1,
#             "script": "libs/vulners.nse",
#             "show_open_ports": 1
#         },
#         is_valid=True
#     )


if __name__ == "__main__":
    test_generic_features()
    # TODO: Fix "No PID found" error
    # test_nmap_vulners()
