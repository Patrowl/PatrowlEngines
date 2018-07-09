## Description
PatrOwl Nmap REST API engine

## Pre-requisites (must be installed before)
- Python 2.7 + pip + virtualenv
- Nmap

# Install notes
- Install python packages on system (use virtualenv)
```
cd PatrowlEngines/engines/nmap
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```
- Create a configuration file (see nmap.json.sample) named 'nmap.json', and customize the following options `"path": "/path/to/bin/nmap"`
- Start the engine (require sudo/root access):
```
sudo env/bin/python engine-nmap.py [--port 5001] [--host 0.0.0.0] [--debug]
```
> Note the use of `env/bin/python` allowing the reference of the python modules within the virtualenv 

## Testing URLs
http://0.0.0.0:5001/engines/nmap/test
http://0.0.0.0:5001/engines/nmap/status
http://0.0.0.0:5001/engines/nmap/info

## Testing script
```
import json, requests, time  

print("TEST CASE: test_scan_nmap")
post_data = {
    "assets": [{
        "id": 2,
        "value": "8.8.8.8",
        "criticity": "low",
        "datatype": "ip"
    },{
        "id": 3,
        "value": "patrowl.io",
        "criticity": "high",
        "datatype": "domain"
    }],
    "options": {
        "ports": ['53', '56', '80', '443'],
        "no_ping": 0,
        "no_dns": 0,
        "detect_service_version": 1
    },
    "scan_id": "666"
}
r = requests.post(url='http://0.0.0.0:5001/engines/nmap/startscan',
           data=json.dumps(post_data),
           headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
```
