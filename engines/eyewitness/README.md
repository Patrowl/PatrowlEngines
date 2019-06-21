## Description
CetStream REST API engine

## Dependencies
- Python 3
- `pip3 install -r requirements.txt`
- `cd /opt; git clone https://github.com/FortyNorthSecurity/EyeWitness.git`
- Follow EyeWitness documentation to setup

## Testing URLs

```bash
EYEWITNESS_ENGINE_URL=http://localhost:5018/engines/eyewitness
ASSET_FQDN=domain.net

# Start scan
curl "${EYEWITNESS_ENGINE_URL}"/startscan -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {}, \"assets\": [{\"datatype\": \"domain\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_FQDN\"}], \"engine_id\": 9}"

# Scan status
curl "${EYEWITNESS_ENGINE_URL}"/status/1

# Get findings (works only once and delete the report)
curl "${EYEWITNESS_ENGINE_URL}"/getfindings/1
```
