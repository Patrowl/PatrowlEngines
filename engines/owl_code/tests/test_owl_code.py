import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="owl_code", base_url="http://127.0.0.1:5013/engines/owl_code")
MAX_TIMEOUT = 300   # in seconds

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_owlcode_jar():
    pet.custom_test(
        test_name="owlcode_jar",
        assets=[{
            "id": '1',
            "value": "https://github.com/TheHive-Project/Cortex.git",
            "criticity": 'low',
            "datatype": 'url'
        }],
        scan_policy={
            "scan_jar": True,
           "repo_type": "git"
        },
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    owlcode_jar()
