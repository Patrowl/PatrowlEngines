# DEV STATUS: STILL IN BETA

## Description
WPScan engine

## Dependencies
- Python 3
- Install wpscan
- `pip3 install -r requirements.txt`


## Testing URLs

```bash
WPSCAN_ENGINE_URL=http://localhost:5023/engines/wpscan
ASSET_URL=domain.net
ASSET_URL_BIS=patrowl.io

# Start scan
curl "${WPSCAN_ENGINE_URL}"/startscan -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {}, \"assets\": [{\"datatype\": \"url\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_URL\"}, {\"datatype\": \"url\", \"criticity\": \"medium\", \"id\": 2, \"value\": \"$ASSET_URL_BIS\"}], \"engine_id\": 9}"

# Scan status
curl "${WPSCAN_ENGINE_URL}"/status/1

# Get findings (works only once and delete the report)
curl "${WPSCAN_ENGINE_URL}"/getfindings/1
```

# Caveats
- Support 1 asset per scan
