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
    """Generic tests."""
    PET.do_generic_tests()


def test_openvas_default_scan_ip():
    """Scan an IP."""
    PET.custom_test(
        test_name="openvas_default_scan_ip",
        assets=[{
            "id": "1",
            "value": "8.8.8.8",
            "criticity": "low",
            "datatype": "ip"
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


def test_openvas_default_scan_domain():
    """Scan a domain."""
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
# FIXME Temporarily deactivate these tests, as they failed without
# any proper openvas instance set up.
# Add instance creation for travis CI and re-add them
#    test_openvas_default_scan_ip()
#    test_openvas_default_scan_domain()
