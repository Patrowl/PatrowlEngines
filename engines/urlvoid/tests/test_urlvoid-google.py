import json, requests, time, random

ENGINE_BASE_URL = "http://127.0.0.1:5008/engines/urlvoid"
TEST_SCAN_ID = random.randint(1000000, 1999999)
MAX_TIMEOUT = 300   # in seconds
SCAN_POLICY = {
    "max_timeout": MAX_TIMEOUT
}

print("TEST CASE: urlvoid-check_google")

post_data = {
    "assets": [{
        "id" :'1',
        "value" :'https://google.com',
        "criticity": 'medium',
        "datatype": 'url'
    }],
    "options": SCAN_POLICY,
    "scan_id": str(TEST_SCAN_ID)
}

r = requests.post(url="{}/startscan".format(ENGINE_BASE_URL),
           data=json.dumps(post_data),
           headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
print(r.json())
assert r.json()['status'] == "accepted"

# Wait until scan is finished
timeout_start = time.time()
has_error = False
while time.time() < timeout_start + MAX_TIMEOUT:
    r = requests.get(url="{}/status/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
    print(r.json())
    if r.json()["status"] == "FINISHED": break
    elif r.json()["status"] == "ERROR":
        has_error = True
        break
    time.sleep(3)

# Get findings
if not has_error:
    r = requests.get(url="{}/getfindings/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
    print(r.json())
    assert r.json()['status'] == "success"

    # Get report
    r = requests.get(url="{}/getreport/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
    print(r.json())
    assert r.json()['scan']['status'] == "FINISHED"
