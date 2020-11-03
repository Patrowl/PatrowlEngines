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

print('TEST CASE: test_scan_droopescan')
post_data = {
    'assets': [{
        'id': 2,
        'value': '<url_to_scan>',
        'criticity': 'medium',
        'datatype': 'url'
    }],
    'options': {
        'scan_wordpress': 1,
    },
    'scan_id': id
}

# Mode
if(mode == 'scan'):
    r = requests.post(
        url='http://0.0.0.0:5021/engines/droopescan/startscan',
        data=json.dumps(post_data),
        headers={'Content-type': 'application/json', 'Accept': 'application/json'}
    )
    print(r.text)
elif(mode == 'results'):
    r = requests.get(url='http://0.0.0.0:5021/engines/droopescan/getfindings/{}'.format(id))
    print(r.text)
# Default is status
elif(mode == 'status'):
    r = requests.get(url='http://0.0.0.0:5021/engines/droopescan/status')
    print(r.text)
else:
    print('Usage:             ./api_droopescan.py -m (scan|results|status) -i <scan_id>')

