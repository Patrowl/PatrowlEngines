# -*- coding: utf-8 -*-
"""
Nessus Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5002/engines/nessus"
MAX_TIMEOUT = 3600

TEST_IP = "51.91.21.212"
TEST_DOMAIN = "www.patrowl.io"
TEST_FQDN = "www.patrowl.io"
TEST_URL = "https://www.patrowl.io"
TEST_IPRANGE = "51.91.21.212-214"
TEST_IPSUBNET = "51.91.21.212/30"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="nessus", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()


def test_nessus_scan_ip():
    """Scan an IP."""
    r = PET.custom_test(
        test_name="nessus_scan_ip",
        assets=[{
            "id": "1",
            "value": TEST_IP,
            "criticity": "low",
            "datatype": "ip"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_domain():
    """Scan a domain."""
    r = PET.custom_test(
        test_name="nessus_scan_domain",
        assets=[{
            "id": "1",
            "value": TEST_DOMAIN,
            "criticity": "low",
            "datatype": "domain"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_fqdn():
    """Scan a FQDN."""
    r = PET.custom_test(
        test_name="nessus_scan_fqdn",
        assets=[{
            "id": "1",
            "value": TEST_FQDN,
            "criticity": "low",
            "datatype": "fqdn"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_url():
    """Scan an URL."""
    r = PET.custom_test(
        test_name="nessus_scan_url",
        assets=[{
            "id": "1",
            "value": TEST_URL,
            "criticity": "low",
            "datatype": "url"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_iprange():
    """Scan an IP range."""
    r = PET.custom_test(
        test_name="nessus_scan_iprange",
        assets=[{
            "id": "1",
            "value": TEST_IPRANGE,
            "criticity": "low",
            "datatype": "ip-range"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_ipsubnet():
    """Scan an IP subnet."""
    r = PET.custom_test(
        test_name="nessus_scan_ipsubnet",
        assets=[{
            "id": "1",
            "value": TEST_IPSUBNET,
            "criticity": "low",
            "datatype": "ip-subnet"
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


def test_nessus_scan_all_datatypes():
    """Scan asset from all datatypes."""
    r = PET.custom_test(
        test_name="nessus_scan_all_datatypes",
        assets=[
            {"id": "1", "value": TEST_IPSUBNET, "criticity": "low", "datatype": "ip-subnet"},
            {"id": "2", "value": TEST_IPRANGE, "criticity": "low", "datatype": "ip-range"},
            {"id": "3", "value": TEST_URL, "criticity": "low", "datatype": "url"},
            {"id": "4", "value": TEST_FQDN, "criticity": "low", "datatype": "fqdn"},
            {"id": "5", "value": TEST_DOMAIN, "criticity": "low", "datatype": "domain"},
            {"id": "6", "value": TEST_IP, "criticity": "low", "datatype": "ip"},
        ],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "action": "scan",
            "policy": "DEFAULT.nessus"
        },
        is_valid=True
    )
    print(r)


if __name__ == "__main__":
    test_generic_features()
    test_nessus_scan_ip()
    test_nessus_scan_domain()
    test_nessus_scan_fqdn()
    test_nessus_scan_url()
    test_nessus_scan_iprange()
    test_nessus_scan_ipsubnet()
    test_nessus_scan_all_datatypes()
