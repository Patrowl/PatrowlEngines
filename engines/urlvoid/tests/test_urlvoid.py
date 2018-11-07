from PatrowlEnginesUtils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="urlvoid", base_url="http://127.0.0.1:5008/engines/urlvoid")
MAX_TIMEOUT = 600


# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_urlvoid_check_google():
    pet.custom_test(
        test_name="urlvoid_check_google",
        assets=[{
            "id": '1',
            "value": 'https://google.com',
            "criticity": 'high',
            "datatype": 'url'
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT
        },
        is_valid=True
    )


def test_urlvoid_check_lifehacker():
    pet.custom_test(
        test_name="urlvoid_check_lifehacker_com",
        assets=[{
            "id": '1',
            "value": 'https://lifehacker.com',
            "criticity": 'high',
            "datatype": 'url'
        }],
        scan_policy={
            "max_timeout": MAX_TIMEOUT
        },
        is_valid=True
    )


if __name__ == '__main__':
    test_generic_features()
    test_urlvoid_check_google()
    test_urlvoid_check_lifehacker()
