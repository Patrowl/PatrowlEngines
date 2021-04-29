![](https://github.com/Patrowl/PatrowlDocs/blob/master/images/logos/logo-patrowl-light.png)

[![Join the chat at https://gitter.im/Patrowl/Support](https://badges.gitter.im/Patrowl/Support.png)](https://gitter.im/Patrowl/Support)
[![Build Status](https://travis-ci.com/Patrowl/PatrowlEngines.svg?branch=master)](https://travis-ci.com/Patrowl/PatrowlEngines)
![https://sonarcloud.io/api/project_badges/measure?project=patrowl-engines&metric=alert_status](https://sonarcloud.io/api/project_badges/measure?project=patrowl-engines&metric=alert_status)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/dd892594b17c4b6db850ed519a1596c1)](https://www.codacy.com/app/MaKyOtOx/PatrowlEngines)

# **PatrOwl**
[PatrOwl](https://www.patrowl.io/) is a scalable, free and open-source solution for orchestrating Security Operations.

**PatrowlEngines** is the engine framework and the supported list of engines performing the operations (scans, searches, API calls, ...) on due time. The engines are managed by one or several instance of [PatrowlManager](https://github.com/Patrowl/PatrowlManager/).

# Architecture
![Technical Overview](https://github.com/Patrowl/PatrowlDocs/blob/master/images/userguide/technical-overview.png)

# Installation and deployment
See the [Installation guide](https://github.com/Patrowl/PatrowlDocs/blob/master/installation/installation-guide.md)

# Usage
See the [User guide](https://github.com/Patrowl/PatrowlDocs/blob/master/installation/user-guide.md)

# License
PatrOwl is an open source and free software released under the [AGPL](https://github.com/Patrowl/PatrowlEngines/blob/master/LICENSE) (Affero General Public License). We are committed to ensure that PatrOwl will remain a free and open source project on the long-run.

# Updates
Information, news and updates are regularly posted on [Patrowl.io  Twitter account](https://twitter.com/patrowl_io) and on [the  blog](https://blog.patrowl.io/).

# Contributing
Please see our [Code of conduct](https://github.com/Patrowl/PatrowlDocs/blob/master/support/code_of_conduct.md). We welcome your contributions. Please feel free to fork the code, play with it, make some patches and send us pull requests via [issues](https://github.com/Patrowl/PatrowlEngines/issues).

# Support
Please [open an issue on GitHub](https://github.com/Patrowl/PatrowlEngines/issues) if you'd like to report a bug or request a feature. We are also available on [Gitter](https://gitter.im/Patrowl/Support) to help you out.

If you need to contact the project team, send an email to <getsupport@patrowl.io>.

# Roadmap
- [ ] WhatWeb
- [ ] CLAIR (Container Security)
- [ ] AquaSecurity
- [P] CheckMarx
- [ ] Tenable.io
- [ ] Acunetix
- [ ] Qualys
- [ ] CyberWatch

# Awesome engines from Community
- [PingCastle](https://github.com/vletoux/PingCastlePatrOwl) by @vletoux (see https://www.pingcastle.com/)

# Pro Edition and SaaS
A commercial Pro Edition is available and officially supported by the PatrOwl company. It includes following extra and awesome engines:
- [x] ZAP (Web scanner)
- [x] Nikto (Web scanner)
- [x] Microsoft Cloud App Security (CASB alerts)
- [x] CloudSploit (Cloud security assessment for AWS, GCP and Azure)
- [x] SonarQube (Code quality and security)
- [x] Checkmarx (Code quality and security)
- [x] TFSec (Terraform security)
- [x] Nuclei (Vulnerability scanner)
- [x] Git-leaks (Secret leaks finder in GIT repositories)

This version is also available on the official SaaS platform.
See: https://patrowl.io/get-started

# Commercial Services
Looking for advanced support, training, integration, custom developments, dual-licensing ? Contact us at getsupport@patrowl.io

# Security contact
Please disclose any security-related issues or vulnerabilities by emailing security@patrowl.io, instead of using the public issue tracker.

# Copyright
Copyright (C) 2018-2021 Nicolas MATTIOCCO ([@MaKyOtOx](https://twitter.com/MaKyOtOx) - nicolas@patrowl.io)

# Travis (CI) build status
| Branch  | Status  |
|---|---|
| master | [![Build Status](https://travis-ci.com/Patrowl/PatrowlEngines.svg?branch=master)](https://travis-ci.com/Patrowl/PatrowlEngines) |
| develop | [![Build Status](https://travis-ci.com/Patrowl/PatrowlEngines.svg?branch=develop)](https://travis-ci.com/Patrowl/PatrowlEngines) |

# Snyk (Vulnerabilities)  status
| Engine  | Status  |
|---|---|
| arachni  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Farachni%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Farachni%2Frequirements.txt)  |
| cortex  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fcortex%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fcortex%2Frequirements.txt)  |
| nessus  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fnessus%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fnessus%2Frequirements.txt)  |
| nmap  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fnmap%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fnmap%2Frequirements.txt)  |
| owl_code  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fowl_code%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fowl_code%2Frequirements.txt)  |
| owl_dns  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fowl_dns%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fowl_dns%2Frequirements.txt)  |
| owl_leaks  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fowl_leaks%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fowl_leaks%2Frequirements.txt)  |
| ssllabs  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fssllabs%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fssllabs%2Frequirements.txt)  |
| urlvoid  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Furlvoid%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Furlvoid%2Frequirements.txt)  |
| virustotal  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fvirustotal%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fvirustotal%2Frequirements.txt)  |
| wpscan  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fwpscan%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fwpscan%2Frequirements.txt)  |
| cybelangel  | [![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlEngines/badge.svg?targetFile=engines%2Fcybelangel%2Frequirements.txt)](https://snyk.io/test/github/Patrowl/PatrowlEngines?targetFile=engines%2Fcybelangel%2Frequirements.txt)  |
