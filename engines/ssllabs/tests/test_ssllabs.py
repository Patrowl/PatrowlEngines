#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
SSLLabs Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5004/engines/ssllabs"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="ssllabs", base_url=BASE_URL)

def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()

def test_ssllabs_check_google():
    """ custom tests """
    PET.custom_test(
        test_name="ssllabs_check_google",
        assets=[{
            "id": "1",
            "value": "https://www.google.com",
            "criticity": "high",
            "datatype": "url"
        }],
        scan_policy={},
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_ssllabs_check_google()
