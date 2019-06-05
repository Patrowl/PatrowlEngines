#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
OWL CODE Tests
"""

# Own library imports
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://127.0.0.1:5013/engines/owl_code"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="owl_code", base_url=BASE_URL)
MAX_TIMEOUT = 300   # in seconds

def test_generic_features():
    """ generic tests """
    PET.do_generic_tests()

# def test_owlcode_jar():
#     """ custom tests """
#     PET.custom_test(
#         test_name="owlcode_jar",
#         assets=[{
#             "id": "1",
#             "value": "https://github.com/TheHive-Project/Cortex.git",
#             "criticity": "low",
#             "datatype": "url"
#         }],
#         scan_policy={
#             "scan_jar": True,
#             "repo_type": "git"
#         },
#         is_valid=True
#     )

if __name__ == "__main__":
    test_generic_features()
    #test_owlcode_jar()
