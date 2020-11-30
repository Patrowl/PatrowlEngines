## Description
DNS REST API engine

## Dependencies
- Python 3 + pip
- [Sublist3r](https://github.com/Patrowl/Sublist3r/)
- [dnstwist](https://github.com/elceef/dnstwist/)
- See requirements.txt for others python packages (use "pip3 install -r requirements.txt")

## Install
Use the installation script
```
./install.sh
```

## Todolist
- Expand contacts info in separate issues (advanced Whois)
- Manage domain zone transfers (AXFR, IXFR)
- Find potential typosquatting domains (dnstwist/URLCrazy+IDN homograph + TLD extensions)
- Exception Management
  * try/except calls to external modules (python-whois and Sublist3r)
  * Check whois with invalid domain names

## Workaround
### MacOs

If the engine fails to resolve domains, consider setting the following env parameter:
```
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```
### Ulimit (max open files)
```
ulimit -Sn 10000
docker run --ulimit	nofile=10000:10000 patrowl/engine-owl_dns
```

## Testing URLs
http://0.0.0.0:5006/engines/owl_dns/test
http://0.0.0.0:5006/engines/owl_dns/info
http://0.0.0.0:5006/engines/owl_dns/status

## Other interesting links & tools
https://publicsuffix.org/list/effective_tld_names.dat
https://github.com/darkoperator/dnsrecon
https://github.com/TheRook/subbrute
https://bitbucket.org/richardpenman/pywhois
