import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="cortex", base_url="http://127.0.0.1:50091/engines/cortex")
time.sleep(90)

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_cortex_check_google():
    pet.custom_test(
        test_name="cortex_check_google",
        assets=[{
            "id" :'1',
            "value" :'8.8.8.8',
            "criticity": 'high',
            "datatype": 'ip'
        }],
        scan_policy={
            "max_timeout": 3600,
            "summary": True,
            "use_analyzers": [
                "Abuse_Finder_2_0",
                "MaxMind_GeoIP_3_0",
                ],
            "all_datatype_analyzers": False,
            "get_artifacts": False,
            "display_failures": False
        },
        is_valid=True
    )

def test_cortex_check_google_artifacts():
    pet.custom_test(
        test_name="cortex_check_google_artifacts",
        assets=[{
            "id" :'1',
            "value" :'8.8.8.8',
            "criticity": 'high',
            "datatype": 'ip'
        }],
        scan_policy={
            "max_timeout": 3600,
            "summary": True,
            "use_analyzers": [
                "Abuse_Finder_2_0",
                "MaxMind_GeoIP_3_0",
                ],
            "all_datatype_analyzers": False,
            "get_artifacts": True,
            "display_failures": False
        },
        is_valid=True
    )

def test_cortex_check_google_all_analyzers():
    pet.custom_test(
        test_name="cortex_check_google_all_analyzers",
        assets=[{
            "id" :'1',
            "value" :'8.8.8.8',
            "criticity": 'high',
            "datatype": 'ip'
        }],
        scan_policy={
            "max_timeout": 3600,
            "summary": True,
            "all_datatype_analyzers": True,
            "get_artifacts": True,
            "display_failures": False
        },
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    test_cortex_check_google()
    test_cortex_check_google_artifacts()
    test_cortex_check_google_all_analyzers()
