## Description
DNS REST API engine

## Dependancies
- Python 2.7 + pip
- Sublist3r (see: https://github.com/aboul3la/Sublist3r) and update owl_dns.json with installation path
- See requirements.txt for others python packages (use "pip install -r requirements.txt")


## Todolist
- Expand contacts info in separate issues (advanced Whois)
- Manage domain zone transfers (AXFR, IXFR)
- Find potential typosquatting domains (dnstwist/URLCrazy+IDN homograph + TLD extensions)
- Exception Management
  * try/except calls to external modules (python-whois and Sublist3r)
  * Check whois with invalid domain names

## Testing URLs
http://0.0.0.0:5006/engines/owl_dns/test

## Dependencies
https://github.com/joepie91/python-whois
https://github.com/aboul3la/Sublist3r


## Other tools
https://github.com/darkoperator/dnsrecon
[https://github.com/TheRook/subbrute]
[https://bitbucket.org/richardpenman/pywhois]
