# DEV STATUS: STILL IN BETA

## Description
WPScan engine

## Dependencies
- Python 3
- `pip3 install -r requirements.txt`


## Testing URLs

```bash
WPSCAN_ENGINE_URL=http://localhost:5023/engines/wpscan
ASSET_FQDN=domain.net

# Start scan
curl "${WPSCAN_ENGINE_URL}"/startscan -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {}, \"assets\": [{\"datatype\": \"domain\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_FQDN\"}], \"engine_id\": 9}"

# Scan status
curl "${WPSCAN_ENGINE_URL}"/status/1

# Get findings (works only once and delete the report)
curl "${WPSCAN_ENGINE_URL}"/getfindings/1
```
