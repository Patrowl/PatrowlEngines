## Description
Nessus engine (online service)

## Dependencies
- Python 3 + pip
- Nessus instance
- See requirements.txt for others python packages (use "pip3 install -r requirements.txt")

## Install notes
- Install python packages on system (use virtualenv)
	* cd PatrowlEngines/engines/nessus
	* virtualenv env --python=python3
	* source env/bin/activate
	* pip3 install -r requirements.txt

- Install the Nessus python cli and apply the patch
	* makdir -p external-libs && cd external-libs
	* git clone https://github.com/tenable/nessrest
	* cd nessrest && git reset --hard af28834d6253db0d00e3ab46ab259dd5bc903063
	* git apply ../../etc/ness6rest.patch
	* pip3 install --trusted-host pypi.python.org -e $PWD/nessrest/

- Upload scan policy files on your Nessus instance:
  * Upload .nessus files located in etc/

- Create a configuration file (see nessus.json.sample) named 'nessus.json', and customize the following options:
  * "server_host": "NESSUS_IP",
	* "server_port": "8834",
	* "server_username": "NESSUS_USERNAME",
	* "server_password": "NESSUS_PASSWORD",

You can also use API credentials:
	* "access_key": "xxxxxxxx",
	* "secret_key": "yyyyyyyy",

- Start the engine:
  * python engine-nessus.py [--port 5002] [--host 0.0.0.0] [--debug]


## Sample policies
- Unauthenticated scan
{'action': 'scan', 'policy': 'DEFAULT.nessus'}

- Authenticated scan
{'action': 'scan', 'policy': 'DEFAULT.nessus', 'credentials': [{'type': 'windows_password', 'password': 'mypass', 'username': 'nicolas'}, {'type': 'ssh_password', 'password': 'mypass', 'username': 'nicolas'}, {'type': 'ssh_password', 'password': 'mypass2', 'username': 'nicolas2'}]}

- Get report (don't scan)
{'name': 'Scan Externe - IP Prod', 'action': 'getreports'}


http://0.0.0.0:5002/engines/nessus/_get_scanlist
http://0.0.0.0:5002/engines/nessus/_get_scan_status?scan_id=182
http://0.0.0.0:5002/engines/nessus/stopscan?scan_id=184
http://0.0.0.0:5002/engines/nessus/genreport?scan_id=184
http://0.0.0.0:5002/engines/nessus/genreport?scan_id=184&format=csv
http://0.0.0.0:5002/engines/nessus/getreport?scan_id=184&format=csv
http://0.0.0.0:5002/engines/nessus/getresults?scan_id=184
