# DEV STATUS: STILL IN BETA

## Description
CybelAngel REST API engine

The purpose of this engine is to automatically add `malicious websites` from CybelAngel in PatrowlManager.

The assets used must be the asset groups from patrowl and the keywords from cybelangel.


## Dependencies
- Python 3.8+
- `pip3 install -r requirements.txt`
- Copy `cybelangel.json.sample` to `cybelangel.json` and configure it

## Testing URLs

```bash
CYBELANGEL_ENGINE_URL=http://localhost:5016/engines/cybelangel
ASSET_DOMAIN=domain.net

# Start scan
curl "${CYBELANGEL_ENGINE_URL}/startscan" -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {\"since\": \"9999\"}, \"assets\": [{\"datatype\": \"domain\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_DOMAIN\"}], \"engine_id\": 9}"

# Scan status
curl "${CYBELANGEL_ENGINE_URL}/status/1"

# Get findings (works only once and delete the report)
curl "${CYBELANGEL_ENGINE_URL}/getfindings/1"

```

## Patrowl Manager

### Fetch almost everything

```
Engine: CYBELANGEL

Options: {"since": "999999"}

```

### Fetch last hour (good for periodically checks)

```
Engine: CYBELANGEL

Options: {"since": "3600"}

```
