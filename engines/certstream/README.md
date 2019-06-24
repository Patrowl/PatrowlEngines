# DEV STATUS: STILL IN BETA

## Description
CertStream REST API engine

## Dependencies
- Python 3
- `pip3 install -r requirements.txt`
- `git clone https://github.com/nbeguier/CertStreamMonitor.git`
- `pip3 install -r CertStreamMonitor/requirements.txt`
- Configure CertStreamMonitor and start a stream
- Configure the engine and specify CertStreamMonitor configuration file
- Run `scanhost.py` occasionally


## Testing URLs

```bash
CERTSTREAM_ENGINE_URL=http://localhost:5017/engines/certstream
ASSET_FQDN=domain.net

# Start scan
curl "${CERTSTREAM_ENGINE_URL}"/startscan -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {\"since\": \"9999\"}, \"assets\": [{\"datatype\": \"domain\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_FQDN\"}], \"engine_id\": 9}"

# Scan status
curl "${CERTSTREAM_ENGINE_URL}"/status/1

# Get findings (works only once and delete the report)
curl "${CERTSTREAM_ENGINE_URL}"/getfindings/1
```

## Patrowl Manager

### Fetch almost everything

```
Engine: CERTSTREAM

Options: {"since": "999999"}

Scopes: E-Reputation

```

### Fetch last hour (good for periodically checks)

```
Engine: CERTSTREAM

Options: {"since": "3600"}

Scopes: E-Reputation

```
