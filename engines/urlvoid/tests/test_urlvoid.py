#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
URLVOID Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5008/engines/urlvoid"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="urlvoid", base_url=BASE_URL)
MAX_TIMEOUT = 600

def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()

def test_urlvoid_check_google():
    """ custom tests """
    PET.custom_test(
        test_name="urlvoid_check_google",
        assets=[{
            "id": "1",
            "value": "https://google.com",
            "criticity": "high",
            "datatype": "url"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT
        },
        is_valid=True
    )

def test_urlvoid_check_lifehacker():
    """ custom tests """
    PET.custom_test(
        test_name="urlvoid_check_lifehacker_com",
        assets=[{
            "id": "1",
            "value": "https://lifehacker.com",
            "criticity": "high",
            "datatype": "url"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT
        },
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_urlvoid_check_google()
    test_urlvoid_check_lifehacker()
