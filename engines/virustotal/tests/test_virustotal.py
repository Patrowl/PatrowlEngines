#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
VIRUSTOTAL Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5007/engines/virustotal"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="virustotal", base_url=BASE_URL)
MAX_TIMEOUT = 600


def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()


def test_virustotal_scan_domain():
    """ custom tests """
    PET.custom_test(
        test_name="virustotal_scan_domain",
        assets=[{
            "id": "1",
            "value": "patrowl.io",
            "criticity": "low",
            "datatype": "domain"
        }, {
            "id": "2",
            "value": "greenlock.fr",
            "criticity": "medium",
            "datatype": "domain"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "do_scan_ip": False,
            "do_scan_domain": True,
            "do_scan_url": False
        },
        is_valid=True
    )


def test_virustotal_scan_ip():
    """ custom tests """
    PET.custom_test(
        test_name="virustotal_scan_ip",
        assets=[{
            "id": "1",
            "value": "8.8.8.8",
            "criticity": "low",
            "datatype": "ip"
        }, {
            "id": "2",
            "value": "213.32.66.58",
            "criticity": "medium",
            "datatype": "ip"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "do_scan_ip": True,
            "do_scan_domain": False,
            "do_scan_url": False
        },
        is_valid=True
    )


def test_virustotal_scan_url():
    """ custom tests """
    PET.custom_test(
        test_name="virustotal_scan_url",
        assets=[{
            "id": "1",
            "value": "https://patrowl.io/",
            "criticity": "low",
            "datatype": "url"
        }, {
            "id": "2",
            "value": "https://google.com",
            "criticity": "medium",
            "datatype": "url"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "do_scan_ip": False,
            "do_scan_domain": False,
            "do_scan_url": True
        },
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_virustotal_scan_domain()
    test_virustotal_scan_ip()
    test_virustotal_scan_url()
