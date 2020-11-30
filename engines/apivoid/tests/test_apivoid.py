#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
APIVOID Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5022/engines/apivoid"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="apivoid", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()

# TODO: Fix "No PID found" error
# def test_apivoid():
#     """Custom tests."""
#     PET.custom_test(
#         test_name="apivoid_test",
#         assets=[{
#             "id": "1",
#             "value": "patrowl.io",
#             "criticity": "low",
#             "datatype": "domain"
#         }],
#         },
#         is_valid=True
#     )


if __name__ == "__main__":
    test_generic_features()
    # TODO: Fix "No PID found" error
    # test_apivoid()
