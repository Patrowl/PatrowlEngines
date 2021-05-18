# DEV STATUS: STILL IN BETA

## Description
SHHGit engine to check your repositories

The purpose of this engine is to automatically check secrets in your github repositories (internal / github.com).

It will scan them with shhgit and try to find any potential secret (AWS, Google API Key, ...)


## Dependencies
- shhgit from (shhgit)[https://github.com/eth0izzle/shhgit#via-go-get], you will need GO
- Python 3.8+
- `pip3 install -r requirements.txt`
- Copy `shhgit.json.sample` to `shhgit.json` and configure it
- `git clone https://github.com/leboncoin/sast-git-leaks/ libs/sast_git_leaks`
- `pip3 install -r libs/sast_git_leaks/requirements.txt`
- Update `MODULE_TOOLS_PATH` in `libs/sast_git_leaks/config/variables.py` to `libs.sast_git_leaks.sast_git_leaks.tools`

## Testing URLs

```bash
SHHGIT_ENGINE_URL=http://localhost:5024/engines/shhgit

# Start scan
curl "${shhgit_ENGINE_URL}/startscan" -XPOST -H 'Accept: application/json' -H 'Content-type: application/json' -d "{\"scan_id\": 1, \"options\": {\"since\": \"9999\"}, \"assets\": [], \"engine_id\": 42}"

# Scan status
curl "${shhgit_ENGINE_URL}/status/1"

# Get findings (works only once and delete the report)
curl "${shhgit_ENGINE_URL}/getfindings/1"

```

## Patrowl Manager

### Fetch almost everything

```
Engine: shhgit

Options: {"since": "999999"}
```

### Fetch last hour (good for periodically checks)

```
Engine: shhgit

Options: {"since": "3600"}
```
