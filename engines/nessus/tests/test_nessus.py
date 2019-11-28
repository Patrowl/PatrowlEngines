#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Nessus Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5002/engines/nessus"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="nessus", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()


if __name__ == "__main__":
    test_generic_features()
