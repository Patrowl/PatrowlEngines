#!/usr/bin/python3
import json, requests, sys, getopt

opts, args = getopt.getopt(sys.argv[1:], 'n:m:')

id = 0
mode = 'status'

for opt, arg in opts:
    if opt == '-n':
        id = arg
    elif opt == '-m':
        mode = arg
    else:
        exit()

print('TEST CASE: test_scan_nmap')
post_data = {
    'assets': [{
        'id': 2,
        'value': '0.0.0.0',
        'criticity': 'medium',
        'datatype': 'ip'
    }],
    'options': {
#	"script": "libs/vulners.nse",
#	"script_args": "newtargets",
	"show_open_ports": 1,
#	"script_output_fields": ["coucou", "gnagna"],
	"detect_service_version": 1,
	"all_scan": 1,
	"detect_os": 1,
	"aggressive_scan": 1
    },
    'scan_id': id
}

# Mode
if(mode == 'scan'):
    r = requests.post(
        url='http://0.0.0.0:5001/engines/nmap/startscan',
        data=json.dumps(post_data),
        headers={'Content-type': 'application/json', 'Accept': 'application/json'}
    )
    print(r.text)
elif(mode == 'results'):
    r = requests.get(url='http://0.0.0.0:5001/engines/nmap/getfindings/{}'.format(id))
    print(r.text)
# Default is status
elif(mode == 'status'):
    r = requests.get(url='http://0.0.0.0:5001/engines/nmap/status')
    print(r.text)
else:
    print('Usage:             ./api_nmap.py -m (scan|results|status) -i <scan_id>')
