## Description
APIVoid Threat analysis engine: https://www.apivoid.com/
APIVoid provides JSON APIs useful for cyber threat analysis, threat detection and
threat prevention.

## Pre-requisites (must be installed before)
- Python 3 + pip + virtualenv

## Available controls performed
- [X] IP Reputation Check
- [X] Domain Reputation Check

## Dependencies
- Python 3 + pip
- See requirements.txt for others python packages (use "pip3 install -r requirements.txt")

## Configuration
set your APIKey in APIVOID_APIKEY environment variable

## Start with Docker
```
docker build . -t engine-apivoid
docker run -p5022:5022 -e APIVOID_APIKEY=XXXXX engine-apivoid
```

## Testing URLs
http://0.0.0.0:5022/engines/apivoid/test
http://0.0.0.0:5022/engines/apivoid/status
http://0.0.0.0:5022/engines/apivoid/info
