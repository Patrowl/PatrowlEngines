import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="nmap", base_url="http://127.0.0.1:5006/engines/owl_dns")
MAX_TIMEOUT = 300   # in seconds

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_owldns_subdomain_enum():
    pet.custom_test(
        test_name="owldns_subdomain_enum",
        assets=[{
            "id" :'1',
            "value" :'patrowl.io',
            "criticity": 'low',
            "datatype": 'domain'
        }, {
            "id" :'2',
            "value" :'uber.com',
            "criticity": 'medium',
            "datatype": 'ip'
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT,
            "do_subdomain_enum": True,
            "do_whois": False,
            "do_advanced_whois": False,
            "do_reverse_dns": False,
            "do_dns_resolve": False,
            "do_subdomains_resolve": False,
            "do_subdomain_bruteforce": False
        },
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    test_owldns_subdomain_enum()
