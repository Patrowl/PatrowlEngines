#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Eyewitness Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5018/engines/eyewitness"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="eyewitness", base_url=BASE_URL)
MAX_TIMEOUT = 600


def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()


if __name__ == "__main__":
    test_generic_features()
