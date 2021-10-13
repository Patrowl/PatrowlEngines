#!/usr/bin/python3
import json, requests, sys, getopt

opts, args = getopt.getopt(sys.argv[1:], 'n:m:t:d:')

id = 0
mode = 'status'
target = "https://google.com"
datatype = "url"

for opt, arg in opts:
    if opt == '-n':
        id = arg
    elif opt == '-m':
        mode = arg
    elif opt == '-t':
        target = arg
    elif opt == '-d':
        datatype = arg
    else:
        exit()

print('TEST CASE: test_scan_sslscan')
post_data = {
    'assets': [{
        'id': 1,
        'value': target,
        'criticity': 'medium',
        'datatype': datatype
    }],
    'options': {
        'ports': ["443"]
    },
    'scan_id': id
}

# Mode
if(mode == 'scan'):
    r = requests.post(
        url='http://0.0.0.0:5014/engines/sslscan/startscan',
        data=json.dumps(post_data),
        headers={'Content-type': 'application/json', 'Accept': 'application/json'}
    )
    print(r.text)
elif(mode == 'results'):
    r = requests.get(url='http://0.0.0.0:5014/engines/sslscan/getfindings/{}'.format(id))
    print(r.text)
# Default is status
elif(mode == 'status'):
    r = requests.get(url='http://0.0.0.0:5014/engines/sslscan/status')
    print(r.text)
else:
    print('Usage:             ./api_sslscan.py -m (scan|results|status) -i <scan_id> -t <target> -d <datatype>')

