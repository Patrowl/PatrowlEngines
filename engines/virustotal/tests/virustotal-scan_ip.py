import json, requests, time, random

ENGINE_BASE_URL = "http://127.0.0.1:5007/engines/virustotal"
TEST_SCAN_ID = random.randint(1000000, 1999999)
MAX_TIMEOUT = 300   # in seconds
SCAN_POLICY = {
    "max_timeout": MAX_TIMEOUT,
    "do_scan_ip": True,
    "do_scan_domain": False,
    "do_scan_url": False
}

print("TEST CASE: virustotal-scan_ip")

post_data = {
    "assets": [{
        "id" :'1',
        "value" :'8.8.8.8',
        "criticity": 'low',
        "datatype": 'ip'
    }, {
        "id" :'2',
        "value" :'213.32.66.58',
        "criticity": 'medium',
        "datatype": 'ip'
    }],
    "options": SCAN_POLICY,
    "scan_id": str(TEST_SCAN_ID)
}

r = requests.post(url="{}/startscan".format(ENGINE_BASE_URL),
           data=json.dumps(post_data),
           headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
print(r.json())

# Wait until scan is finished
timeout_start = time.time()
while time.time() < timeout_start + MAX_TIMEOUT:
    r = requests.get(url="{}/status/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
    print(r.json())
    if r.json()["status"] == "FINISHED":
        break
    time.sleep(3)

# Get findings
r = requests.get(url="{}/getfindings/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
print(r.json())

# Get report
r = requests.get(url="{}/getreport/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
print(r.json())
