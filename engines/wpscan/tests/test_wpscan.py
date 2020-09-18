#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Wpscan Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5023/engines/wpscan"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="wpscan", base_url=BASE_URL)
MAX_TIMEOUT = 600


def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()


if __name__ == "__main__":
    test_generic_features()
