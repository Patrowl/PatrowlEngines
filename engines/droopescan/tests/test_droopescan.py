#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
droopscan Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5021/engines/droopescan"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="droopescan", base_url=BASE_URL)

def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()

def test_droopescan_check_website(website,fqdn):
    """ custom tests """
    PET.custom_test(
        test_name="ssllabs_check_"+website,
        assets=[{
            "id": "1",
            "value": "https://"+fqdn,
            "criticity": "low",
            "datatype": "url"
        }],
        scan_policy={
            "scan_wordpress": 1,
        })

if __name__ == "__main__":
    test_generic_features()
    test_droopescan_check_website("novepha", "www.novepha.fr")
