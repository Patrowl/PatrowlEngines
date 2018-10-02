import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="nessus", base_url="http://127.0.0.1:5002/engines/nessus")

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
# Todo !!

if __name__ == '__main__':
    test_generic_features()
