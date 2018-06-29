## Description
PatrOwl Nmap REST API engine

## Dependancies
- Python 2.7 + pip + virtualenv
- Nmap
- See requirements.txt for others python packages (use "pip install -r requirements.txt")

# Install notes
- Install python packages on system (use virtualenv)
```
cd patrowl/engines/nmap
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```
- Create a configuration file (see nmap.json.sample) named 'nmap.json', and customize the following options `"path": "/path/to/bin/nmap"`
- Start the engine (require sudo/root access):
```
sudo python engine-nmap.py [--port 5001] [--host 0.0.0.0] [--debug]
```

## Testing URLs
http://0.0.0.0:5001/engines/nmap/test
http://0.0.0.0:5001/engines/nmap/startscan?hosts=8.8.8.8&ports=53&options=no_ping
http://0.0.0.0:5001/engines/nmap/startscan?hosts=8.8.8.8&ports=-&options=no_ping
