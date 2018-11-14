import json, requests, time, random
from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="owl_leaks", base_url="http://127.0.0.1:5012/engines/owl_leaks")
MAX_TIMEOUT = 300   # in seconds

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_owlleaks_patrowl():
    pet.custom_test(
        test_name="owlleaks_patrowl",
        assets=[{
            "id" :'1',
            "value" :'patrowl.io',
            "criticity": 'low',
            "datatype": 'keyword'
        }],
        scan_policy={
            "max_timeout": 3600,
            "search_github": False,
            # "search_github": True,
            "github_qualifiers": {
                # "since_period": "30days",
                "from_date": "2010-01-01"
            },
            # "search_twitter": False,
            "search_twitter": True,
            "search_twitter_options": {
                "max_count": 10,
                "extra_kw": ["hack", "attack", "leak", "fuite", "phishing", "ddos"],
                "since": "2017-01-01"
            }
        },
        is_valid=True
    )

if __name__ == '__main__':
    test_generic_features()
    test_owlleaks_patrowl()
