#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
OWL DNS Tests
"""

# Standard library imports
from sys import path
from os.path import abspath, dirname

# Own library imports
path.append(dirname(dirname(abspath(__file__))))
from utils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5006/engines/owl_dns"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="nmap", base_url=BASE_URL)
MAX_TIMEOUT = 300   # in seconds

def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()

def test_owldns_subdomain_enum():
    """ custom tests """
    PET.custom_test(
        test_name="owldns_subdomain_enum",
        assets=[{
            "id" :"1",
            "value" :"patrowl.io",
            "criticity": "low",
            "datatype": "domain"
        }, {
            "id" :"2",
            "value" :"uber.com",
            "criticity": "medium",
            "datatype": "ip"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "do_subdomain_enum": True,
            "do_whois": False,
            "do_advanced_whois": False,
            "do_reverse_dns": False,
            "do_dns_resolve": False,
            "do_subdomains_resolve": False,
            "do_subdomain_bruteforce": False
        },
        is_valid=True
    )

if __name__ == "__main__":
    test_generic_features()
    test_owldns_subdomain_enum()
