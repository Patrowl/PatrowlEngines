import json, requests, time

print ("TEST CASE: test_startscan_censys")

post_data = {
    "assets": ["*.patrowl.io"],
    "options" : {
        "do_scan_valid": True,
        "ignore_changed_certificate": True,
        "changed_certificate_port_test": [443,465,636,993,995,8443,9443],
        "do_scan_trusted": True,
        "verbose": True,
        "do_scan_ca_trusted": True,
        "do_scan_self_signed": True,
        "keyword": ["parsed.subject.organization: \"PatrOwl\""],
        "trusted_self_signed": [],
        "trusted_host":
            [
              "www.patrowl.io",
              "blog.patrowl.io"
            ],
        "trusted_ca_certificate":
            [],
    },
    "scan_id": 666
}

r = requests.post(url='http://127.0.0.1:5009/engines/censys/startscan',
    data=json.dumps(post_data),
    #verify='../../certificat/ca.crt',
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    )
r = requests.get(url='http://127.0.0.1:5009/engines/censys/status/TEST2')
print(r.json())
