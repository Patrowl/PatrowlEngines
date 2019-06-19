## Description
Openvas REST API engine

## Dependencies
- Python 3 + pip
- See requirements.txt for others python packages (use "pip install -r requirements.txt")
- Install Python-gvm
  `mkdir -p libs ; cd libs ; git clone git://github.com/greenbone/python-gvm ; pip3 install -e python-gvm`
- You have to create a new task on OpenVAS and configure the task_id in openvas.json

## Testing URLs

```bash
OPENVAS_ENGINE_URL=http://patrowl-900.domain.net:5016/engines/openvas
ASSET_FQDN=some.asset.domain.net

# Start scan
curl "${OPENVAS_ENGINE_URL}"/startscan -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {\"enable_create_task\": \"False\", \"enable_create_target\": \"False\", \"enable_start_task\": \"False\"}, \"assets\": [{\"datatype\": \"domain\", \"criticity\": \"medium\", \"id\": 1, \"value\": \"$ASSET_FQDN\"}], \"engine_id\": 9}"

# Scan status
curl "${OPENVAS_ENGINE_URL}"/status/1

# Get findings (works only once and delete the report)
curl "${OPENVAS_ENGINE_URL}"/getfindings/1
```

## Patrowl Manager

### Fetch only

```
Engine: OPENVAS

Options: {"enable_create_target": "False", "enable_start_task": "False", "enable_create_task": "False"}

Scopes: System infrastructure

```

### Create and Run

```
Engine: OPENVAS

Options: {"enable_create_target": "True", "enable_start_task": "True", "enable_create_task": "True"}

Scopes: System infrastructure

```
