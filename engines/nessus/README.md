## Description
Nessus engine (online service)

## Dependancies
- Python 2.7 + pip
- Nessus instance
- See requirements.txt for others python packages (use "pip3 install -r requirements.txt")

# Install notes
- Install python packages on system (use virtualenv)
	* cd patrowl/engines/nessus
	* virtualenv env
	* source env/bin/activate
	* pip3 install -r requirements.txt
- Create a configuration file (see nessus.json.sample) named 'nessus.json', and customize the following options:
  * "server_host": "NESSUS_IP",
	* "server_port": "8834",
	* "server_username": "NESSUS_USERNAME",
	* "server_password": "NESSUS_PASSWORD",
- Start the engine:
  * python engine-nessus.py [--port 5002] [--host 0.0.0.0] [--debug]


http://0.0.0.0:5002/engines/nessus/startscan?policy=NESSUS_POLICY_NETWORK_SCAN.nessus&targets=8.8.8.8,8.8.4.4

http://0.0.0.0:5002/engines/nessus/_get_scanlist
http://0.0.0.0:5002/engines/nessus/_get_scan_status?scan_id=182
http://0.0.0.0:5002/engines/nessus/stopscan?scan_id=184
http://0.0.0.0:5002/engines/nessus/genreport?scan_id=184
http://0.0.0.0:5002/engines/nessus/genreport?scan_id=184&format=csv
http://0.0.0.0:5002/engines/nessus/getreport?scan_id=184&format=csv
http://0.0.0.0:5002/engines/nessus/getresults?scan_id=184
