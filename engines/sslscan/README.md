## Description
SSLScan Engine (Community Edition) 1.4.30

https://github.com/rbsec/sslscan

## Usage
### Docker
* Build container:
```
docker build --rm -t patrowl/engine-sslscan .
```

* Run container:
```
docker run -d -p 5014:5014 patrowl/engine-sslscan
```

### Sources
* Install Python 3 + pip
* See requirements.txt for others python packages (use "pip3 install -r requirements.txt")
* SSLScan:
  * MACOSX: `cd sslscan && make static`
  * Linux:
```
    git clone https://github.com/rbsec/sslscan.git && cd sslscan && make static
```
* Zlib:
  * Ubuntu: `sudo apt-get install zlib1g-dev`
  * Centos/RHEL: `sudo yum install zlib-devel`
* Copy sample file and modify it suiting your needs
```
cp engine-sslscan.json.sample engine-sslscan.json
```
* Launch:
```
 python3 engine-sslscan.py --port=5014 --host=0.0.0.0 --debug
```

## Todo:
Support IP range and IP subnets
