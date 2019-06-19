#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
OpenVAS Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5016/engines/openvas"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="openvas", base_url=BASE_URL)
MAX_TIMEOUT = 600


def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()


def test_openvas_default_scan_domain():
    """ custom tests """
    PET.custom_test(
        test_name="openvas_default_scan_domain",
        assets=[{
            "id": "1",
            "value": "patrowl.io",
            "criticity": "low",
            "datatype": "domain"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "credential_name": False,
            "scan_config_name": False,
            "enable_create_target": False,
            "enable_create_task": False,
            "enable_start_task": False
        },
        is_valid=True
    )


if __name__ == "__main__":
    test_generic_features()
    test_openvas_default_scan_domain()
