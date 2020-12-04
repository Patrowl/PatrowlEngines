#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
NMAP Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5001/engines/nmap"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="nmap", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()


def test_nmap_scan_ip():
    """Custom tests."""
    PET.custom_test(
        test_name="nmap_scan_ip",
        assets=[{
            "id": "1",
            "value": "8.8.8.8",
            "criticity": "low",
            "datatype": "ip"
        }],
        scan_policy={
            "no_ping": 0,
            "ports": [
                "80",
                "22",
                "443",
                "56",
                "25"
            ],
            "detect_service_version": 1,
            "show_open_ports": 1
        },
        is_valid=True,
        scan_id="3-3"
    )


if __name__ == "__main__":
    # test_generic_features()
    test_nmap_scan_ip()
