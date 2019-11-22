#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
OWL_REQUEST Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5019/engines/owl_request"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="curl", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()


def test_owl_request_check_google():
    """Custom tests."""
    PET.custom_test(
        test_name="owl_request_check_http_get",
        assets=[{
            "id": "1",
            "value": "https://www.google.com",
            "criticity": "high",
            "datatype": "url"
        }],
        scan_policy={
            "scheme": "http",
            "http_method": "get",
            "tls_insecure": True
        },
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_owl_request_check_google()
