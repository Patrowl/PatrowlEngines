## Description
Burp REST API engine
use https://github.com/vmware/burp-rest-api/ as wrapper to access Burp as REST API

Start the engine:
$ cd FullScan/engines/
$ source env/bin/activate
$ sudo python burp/engine-burp.py

## Usage tips
- Use Python3
- Sudo

## Todolist by file
engine-burp.py
- generate formatted report
- start a scan with of without spidering
- check spidering status
- import sitemap from file or post data request
- stop active scans based on url
- manage project and user options
- check and load extensions on startup
- normalize I/O


extres/burp-rest-api:
- get spider status (check if forms queued remains)
- show scan queue on URL base
- show scan status (scan progress) by url or base url
- delete url or base url from active queue scan
- pause scanner
- load burp extensions -> add entries in user options file and maintain in configuration the extension versions
- check extensions on startup (use callback	isExtensionBapp())


http://localhost:5000/engines/burp/_addto_scope?url=https://blog.thehive-project.org
http://localhost:5000/engines/burp/_get_scope?url=https://blog.thehive-project.org


java -jar /Users/GreenLock/Documents/Projets/patrowl/engines/burp/extres/burp-rest-api-1.0.1.jar -Xmx2g --headless.mode=false --server.port=5001 --project-file=/Users/GreenLock/Documents/Projets/patrowl/engines/burp/tmp/project-file.burp
