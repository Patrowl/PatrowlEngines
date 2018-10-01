import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="owl_leaks", base_url="http://127.0.0.1:5012/engines/owl_leaks")
MAX_TIMEOUT = 300   # in seconds

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
# def test_owlleaks_subdomain_enum():
#     pet.custom_test(
#         test_name="owldns_subdomain_enum",
#         assets=[{
#             "id" :'1',
#             "value" :'patrowl.io',
#             "criticity": 'low',
#             "datatype": 'domain'
#         }],
#         scan_policy={
#             ...
#         },
#         is_valid=True
#     )

if __name__ == '__main__':
    test_generic_features()
    #test_owlleaks_subdomain_enum()
