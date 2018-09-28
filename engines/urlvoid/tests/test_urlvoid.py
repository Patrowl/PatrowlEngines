import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="urlvoid", base_url="http://127.0.0.1:5008/engines/urlvoid")

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_urlvoid_check_google():
    pet.custom_test(
        test_name="urlvoid_check_google",
        assets=[{
            "id" :'1',
            "value" :'https://www.google.com',
            "criticity": 'high',
            "datatype": 'url'
        }],
        scan_policy={},
        is_valid=True
    )

def test_urlvoid_check_lifehacker():
    pet.custom_test(
        test_name="urlvoid_check_lifehacker_com",
        assets=[{
            "id" :'1',
            "value" :'https://lifehacker.com',
            "criticity": 'high',
            "datatype": 'url'
        }],
        scan_policy={},
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    test_urlvoid_check_google()
    test_urlvoid_check_lifehacker()
