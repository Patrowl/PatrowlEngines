#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Curl Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5019/engines/curl"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="curl", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()


def test_curl_check_google():
    """Custom tests."""
    PET.custom_test(
        test_name="curl_check_google",
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
    test_curl_check_google()
