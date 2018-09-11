import json, requests, time, random

ENGINE_BASE_URL = "http://127.0.0.1:5001/engines/nmap"
TEST_SCAN_ID = random.randint(1000000, 1999999)
MAX_TIMEOUT = 300   # in seconds
SCAN_POLICY = {
  "no_ping":0,
  "no_dns":1,
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
}


print("TEST CASE: nmap-vulners-script")

post_data = {
    "assets": [{
        "id" :'1',
        "value" :'patrowl.io',
        "criticity": 'low',
        "datatype": 'domain'
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

# Get Report
r = requests.get(url="{}/getreport/{}".format(ENGINE_BASE_URL, TEST_SCAN_ID))
print(r.json())
