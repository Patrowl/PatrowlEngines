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

if __name__ == "__main__":
    test_generic_features()
# FIXME Temporarily remove tests that require an openvas instance
