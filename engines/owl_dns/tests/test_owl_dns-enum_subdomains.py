import json, requests, time, random

ENGINE_BASE_URL = "http://127.0.0.1:5006/engines/owl_dns"
TEST_SCAN_ID = random.randint(1000000, 1999999)
MAX_TIMEOUT = 300   # in seconds
SCAN_POLICY = {
    "max_timeout": MAX_TIMEOUT,
    "do_subdomain_enum": True,
    "do_whois": False,
    "do_advanced_whois": False,
    "do_reverse_dns": False,
    "do_dns_resolve": False,
    "do_subdomains_resolve": False,
    "do_subdomain_bruteforce": False
}

print("TEST CASE: owl_dns-enum_subdomains")
post_data = {
    "assets": [{
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
