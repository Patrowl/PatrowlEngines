#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PyTest cases for SSLScan engine."""

from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(
    engine_name="sslscan",
    base_url="http://127.0.0.1:5014/engines/sslscan")


def test_sslscan_generic_features():
    """Perform generic tests."""
    pet.do_generic_tests()


def test_sslscan_simple_checks():
    """Perform simple tests."""
    pet.custom_test(
        test_name="sslscan_simple_checks",
        assets=[{
            "id": '1',
            "value": 'https://www.google.com',
            "criticity": 'high',
            "datatype": 'url'
        }, {
            "id": '2',
            "value": 'patrowl.io',
            "criticity": 'high',
            "datatype": 'domain'
        }, {
            "id": '3',
            "value": '8.8.8.8',
            "criticity": 'high',
            "datatype": 'ip'
        }],
        scan_policy={
            "ports": ["443"]
        }
    )


def test_sslscan_selfsigned_certificate():
    """Perform self-signature tests."""
    pet.custom_test(
        test_name="sslscan_selfsigned_certificate",
        assets=[{
            "id": '1',
            "value": 'self-signed.badssl.com',
            "criticity": 'high',
            "datatype": 'domain'
        }],
        scan_policy={}
    )


def test_sslscan_expired_certificate():
    """Perform expired certificate tests."""
    pet.custom_test(
        test_name="sslscan_expired_certificate",
        assets=[{
            "id": '1',
            "value": 'expired.badssl.com',
            "criticity": 'high',
            "datatype": 'domain'
        }],
        scan_policy={}
    )


if __name__ == '__main__':
    test_sslscan_generic_features()
    test_sslscan_simple_checks()
    test_sslscan_selfsigned_certificate()
    test_sslscan_expired_certificate()
