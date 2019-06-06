#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""PyTest cases for SSLScan engine."""

from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(
    engine_name="sslscan",
    base_url="http://127.0.0.1:5014/engines/sslscan")


def test_sslscan_simple_checks():
    """Perform simple tests."""
    pet.custom_test(
        test_name="sslscan_simple_checks",
        assets=[{
            "id": '1',
            "value": 'expired.badssl.com',
            "criticity": 'high',
            "datatype": 'domain'
        }],
        scan_policy={
            "ports": ["443"]
        }
    )


if __name__ == '__main__':
    test_sslscan_simple_checks()
