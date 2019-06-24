#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Certstream Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5017/engines/certstream"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="certstream", base_url=BASE_URL)
MAX_TIMEOUT = 600


def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()


def test_certstream_generic():
    """ custom tests """
    PET.custom_test(
        test_name="test_certstream_generic",
        assets=[{
            "id": "1",
            "value": "patrowl.io",
            "criticity": "low",
            "datatype": "domain"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "since": 9999
        },
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_certstream_generic()
