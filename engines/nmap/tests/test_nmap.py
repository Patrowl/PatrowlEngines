import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="nmap", base_url="http://127.0.0.1:5001/engines/nmap")

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_nmap_vulners():
    pet.custom_test(
        test_name="nmap_vulners",
        assets=[{
            "id" :'1',
            "value" :'patrowl.io',
            "criticity": 'low',
            "datatype": 'domain'
        }],
        scan_policy={
          "no_ping":0,
          "ports":[
            "80",
            "22",
            "443",
            "56",
            "25"
          ],
          "detect_service_version":1,
          "script":"libs/vulners.nse",
          "show_open_ports":1
        },
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    test_nmap_vulners()
