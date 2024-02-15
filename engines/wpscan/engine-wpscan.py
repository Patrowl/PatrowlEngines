#!/usr/bin/env python3
"""
WPSCAN PatrOwl engine application.

Copyright (C) 2024 Nicolas Mattiocco - @MaKyOtOx
Licensed under the AGPLv3 License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from hashlib import sha256
from logging import getLogger
from os.path import dirname, exists, realpath
from sys import argv, modules
from threading import Thread
from time import time
import json
import os
import re
import subprocess
import psutil
from flask import Flask, request, jsonify

# Own library imports
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions
from requests import Session

# Debug
# from pdb import set_trace as st

LOG = getLogger("werkzeug")

app = Flask(__name__)
APP_DEBUG = os.environ.get("DEBUG", "").lower() in ["true", "1", "yes", "y", "on"]
APP_HOST = "0.0.0.0"
APP_PORT = 5023
APP_MAXSCANS = int(os.environ.get("APP_MAXSCANS", 5))
APP_ENGINE_NAME = "wpscan"
APP_BASE_DIR = dirname(realpath(__file__))
VERSION = "1.4.28"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION,
)

this = modules[__name__]
this.keys = []


def get_options(payload):
    """Extract formatted options from the payload."""
    options = {}
    user_opts = payload["options"]
    if isinstance(user_opts, str):
        user_opts = json.loads(user_opts)
    if isinstance(user_opts, str):
        user_opts = json.loads(user_opts)
    options["extra_args"] = ""
    if "extra_args" in user_opts:
        options["extra_args"] = user_opts["extra_args"]
    return options


def get_criticity(score):
    """Return the level of criticity."""
    criticity = "high"
    if score == 0:
        criticity = "info"
    elif score < 4.0:
        criticity = "low"
    elif score < 7.0:
        criticity = "medium"
    return criticity


def get_api_token(api_token_list):
    """Return the API key with the most credits."""
    SESSION = Session()
    top_api_token = None
    top_api_token_credits = 0
    for api_token in api_token_list:
        if not re.fullmatch("[a-zA-Z0-9]+", api_token):
            continue
        try:
            token_status_req = SESSION.get(
                "https://wpscan.com/api/v3/status",
                headers={"Authorization": f"Token token={api_token}"},
            )
        except Exception:
            continue
        if token_status_req.status_code != 200:
            continue
        try:
            requests_remaining = json.loads(token_status_req.text)["requests_remaining"]
        except Exception:
            requests_remaining = 0
        if requests_remaining > top_api_token_credits:
            top_api_token = api_token
            top_api_token_credits = requests_remaining
    return top_api_token


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    return engine.page_not_found()


@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    """Invalid request usage."""
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response


@app.route("/")
def default():
    """Route by default."""
    return engine.default()


@app.route("/engines/wpscan/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/wpscan/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/wpscan/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/wpscan/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/wpscan/info")
def info():
    """Get info on running engine."""
    return engine.info()


@app.route("/engines/wpscan/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/wpscan/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/wpscan/status")
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route("/engines/wpscan/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    has_running_thread = False
    for asset in engine.scans[scan_id]["reports"].keys():
        proc = None
        # Handle missing proc during first status
        if "proc" in engine.scans[scan_id]["reports"][asset]:
            proc = engine.scans[scan_id]["reports"][asset]["proc"]

        if proc and not hasattr(proc, "pid"):
            res.update({"status": "ERROR", "reason": "No PID found"})
            engine.scans[scan_id]["status"] = "ERROR"
            return jsonify(res)

        if not proc or (
            psutil.pid_exists(proc.pid)
            and psutil.Process(proc.pid).status() in ["sleeping", "running"]
        ):
            has_running_thread = True
            res.update(
                {
                    "status": "SCANNING",
                    "info": {
                        asset: {
                            # "pid": proc.pid,
                            # "cmd": engine.scans[scan_id]["reports"][asset]["proc_cmd"]}
                        }
                    },
                }
            )

        elif (
            psutil.pid_exists(proc.pid)
            and psutil.Process(proc.pid).status() == "zombie"
        ):
            psutil.Process(proc.pid).terminate()

    if has_running_thread is False:
        res.update({"status": "FINISHED"})
        engine.scans[scan_id]["status"] = "FINISHED"

    return jsonify(res)


@app.route("/engines/wpscan/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/wpscan/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route("/engines/wpscan/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR + "/wpscan.json"
    if len(argv) > 1 and exists(APP_BASE_DIR + "/" + argv[1]):
        conf_file = APP_BASE_DIR + "/" + argv[1]
    if exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
        engine.scanner["status"] = "READY"
    else:
        LOG.error("Error: config file '{}' not found".format(conf_file))
        return {"status": "error", "reason": "config file not found"}

    if "options" not in engine.scanner:
        LOG.error("Error: You have to specify options")
        return {"status": "error", "reason": "You have to specify options"}

    if "APIToken" not in engine.scanner["options"]:
        LOG.error("Error: You have to specify APIToken in options")
        return {"status": "error", "reason": "You have to specify APIToken in options"}

    if "value" not in engine.scanner["options"]["APIToken"]:
        LOG.error("Error: You have to specify APIToken in options")
        return {"status": "error", "reason": "You have to specify APIToken in options"}

    version_filename = APP_BASE_DIR + "/VERSION"
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        engine.version = version_file.read().rstrip("\n")
        version_file.close()
    LOG.info("[OK] APIToken")


@app.route("/engines/wpscan/reloadconfig", methods=["GET"])
def reloadconfig():
    """Reload engine configuration."""
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/wpscan/startscan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update(
            {
                "status": "error",
                "reason": "Scan refused: max concurrent active scans reached ({})".format(
                    APP_MAXSCANS
                ),
            }
        )
        return jsonify(res)

    status()
    if engine.scanner["status"] != "READY":
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": "scanner not ready",
                    "status": engine.scanner["status"],
                },
            }
        )
        return jsonify(res)

    data = json.loads(request.data.decode("utf-8"))
    if "assets" not in data.keys() or "scan_id" not in data.keys():
        res.update(
            {
                "status": "refused",
                "details": {"reason": "arg error, something is missing ('assets' ?)"},
            }
        )
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, something is missing ('asset.value')",
                }
            )
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, bad value for '{}' datatype (not supported)".format(
                        asset["value"]
                    ),
                }
            )
            return jsonify(res)

        assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    if data["scan_id"] in engine.scans.keys():
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": "scan '{}' is probably already launched".format(
                        data["scan_id"]
                    ),
                },
            }
        )
        return jsonify(res)

    scan = {
        "assets": assets,
        "threads": [],
        "options": data["options"],
        "scan_id": scan_id,
        "status": "STARTED",
        "started_at": int(time() * 1000),
        "findings": {},
    }

    options = get_options(data)

    engine.scanner["options"]["extra_args"] = options["extra_args"]

    engine.scans.update({scan_id: scan})
    for a in engine.scans[scan_id]["assets"]:
        thread = Thread(
            target=_scan_urls,
            args=(
                scan_id,
                a,
            ),
        )
        thread.start()
        engine.scans[scan_id]["threads"].append(thread)

    res.update({"status": "accepted", "details": {"scan_id": scan["scan_id"]}})

    return jsonify(res)


def _scan_urls(scan_id, asset):

    wpscan_cmd = "wpscan"

    wordpress_hostname = asset
    wordpress_hostname_hash = sha256(wordpress_hostname.encode()).hexdigest()

    wpscan_cmd += " --url '{}'".format(wordpress_hostname)
    wpscan_cmd += " --disable-tls-checks"
    wpscan_cmd += " --update"  # Update database
    wpscan_cmd += " --clear-cache"  # Clear cache

    # Patrowl specific User-Agent
    wpscan_cmd += " --ua 'Patrowl Engine WPSCAN v{}'".format(VERSION)

    # Write report on disk
    if "reports" not in engine.scans[scan_id].keys():
        engine.scans[scan_id]["reports"] = {}
    if asset not in engine.scans[scan_id]["reports"].keys():
        engine.scans[scan_id]["reports"][asset] = {}

    engine.scans[scan_id]["reports"][asset]["report_path"] = (
        "{}/results/{}_{}.json".format(APP_BASE_DIR, scan_id, wordpress_hostname_hash)
    )
    wpscan_cmd += " --output '{}'".format(
        engine.scans[scan_id]["reports"][asset]["report_path"]
    )
    wpscan_cmd += " --format json"

    # Add API Token if credits remaining
    api_token = get_api_token(engine.scanner["options"]["APIToken"]["value"])
    LOG.warning(f"Token used is {api_token}")
    if api_token is not None:
        wpscan_cmd += " --api-token '{}'".format(api_token)

    # Extra args
    extra_args = engine.scanner["options"]["extra_args"]
    if re.fullmatch("[a-zA-Z0-9\-_\ :/\.]+", extra_args):
        wpscan_cmd += " " + extra_args

    LOG.debug(wpscan_cmd)

    engine.scans[scan_id]["reports"][asset]["proc"] = subprocess.Popen(
        wpscan_cmd,
        shell=True,
        stdout=open("/dev/null", "w"),
        stderr=open("/dev/null", "w"),
    )
    engine.scans[scan_id]["reports"][asset]["proc_cmd"] = wpscan_cmd

    return True


def get_report(scan_id):
    """Get report."""
    result = dict()
    try:
        result_file = open(
            "results/wpscan_report_{scan_id}.txt".format(scan_id=scan_id), "r"
        )
        result = json.loads(result_file.read())
        result_file.close()
    except Exception:
        return {"status": "ERROR", "reason": "no issues found"}

    return result


def _parse_description(desc):
    res = ""
    for k in desc.keys():
        res += _parse_item(k, desc[k])
    return res


def _parse_item(key, value, prefix=""):
    res = ""
    if key is not None:
        res = "{}{}:".format(prefix, key)
    if isinstance(value, (str, int, bool)):
        return "{} {}\n".format(res, value)

    elif isinstance(value, list):
        values = "{}:\n".format(key)
        for subitem in value:
            values += "{}-".format(prefix) + _parse_item(
                None, subitem, "{}{}".format(prefix, " " * 2)
            )
        return values

    elif isinstance(value, dict):
        if key is None:
            values = "---------\n"
        else:
            values = "{}:\n".format(key)
        for subitem in value.keys():
            if isinstance(value[subitem], (str, int, bool)):
                values += "{}-".format(prefix) + _parse_item(
                    subitem, value[subitem], " "
                )
            else:
                values += "{}- ".format(prefix) + _parse_item(
                    subitem, value[subitem], "{}{}".format(prefix, " " * 2)
                )
        return values
    return res


def _parse_results(scan_id):
    issues = []
    summary = {}

    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    timestamp = int(time() * 1000)

    for asset in engine.scans[scan_id]["reports"].keys():
        with open(
            engine.scans[scan_id]["reports"][asset]["report_path"], "r"
        ) as results_file:
            content = json.loads(results_file.read())

        if "scan_aborted" in content and content["scan_aborted"]:
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": get_criticity(0),
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "http", "parent": asset},
                    "title": "Scan error: {}".format(content["scan_aborted"]).rstrip(),
                    "solution": "n/a",
                    "metadata": {"risk": {"cvss_base_score": 0}},
                    "type": "wpscan_report",
                    "timestamp": timestamp,
                    "description": content["scan_aborted"],
                }
            )
            nb_vulns[get_criticity(0)] += 1
            continue

        # Interesting Entries
        if "interesting_findings" in content and content["interesting_findings"]:
            for interesting_finding in content["interesting_findings"]:
                # Custom: get the Server header
                if interesting_finding["type"] == "headers":
                    for interesting_entry in interesting_finding["interesting_entries"]:
                        if interesting_entry.lower().startswith("server:"):
                            issues.append(
                                {
                                    "issue_id": len(issues) + 1,
                                    "severity": get_criticity(0),
                                    "confidence": "certain",
                                    "target": {
                                        "addr": [asset],
                                        "protocol": "http",
                                        "parent": asset,
                                    },
                                    "title": "Header: {}".format(
                                        interesting_entry
                                    ).rstrip(),
                                    "solution": "n/a",
                                    "metadata": {"risk": {"cvss_base_score": 0}},
                                    "type": "wpscan_report",
                                    "timestamp": timestamp,
                                    "description": _parse_description(
                                        interesting_finding
                                    ),
                                }
                            )
                            nb_vulns[get_criticity(0)] += 1
                # Medium findings
                elif interesting_finding["type"] in ["xmlrpc"]:
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": get_criticity(5),
                            "confidence": "certain",
                            "target": {
                                "addr": [asset],
                                "protocol": "http",
                                "parent": asset,
                            },
                            "title": "XMLRPC enabled",
                            "solution": "n/a",
                            "metadata": {"risk": {"cvss_base_score": 0}},
                            "type": "wpscan_report",
                            "timestamp": timestamp,
                            "description": _parse_description(interesting_finding),
                        }
                    )
                    nb_vulns[get_criticity(5)] += 1
                # Info findings
                else:
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": get_criticity(0),
                            "confidence": "certain",
                            "target": {
                                "addr": [asset],
                                "protocol": "http",
                                "parent": asset,
                            },
                            "title": "Interesting finding: {}".format(
                                interesting_finding["type"]
                            ).rstrip(),
                            "solution": "n/a",
                            "metadata": {"risk": {"cvss_base_score": 0}},
                            "type": "wpscan_report",
                            "timestamp": timestamp,
                            "description": _parse_description(interesting_finding),
                        }
                    )
                    nb_vulns[get_criticity(0)] += 1

        # Themes
        if "main_theme" in content and content["main_theme"]:
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": get_criticity(0),
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "http", "parent": asset},
                    "title": "Theme: {}".format(content["main_theme"]["slug"]).rstrip(),
                    "solution": "n/a",
                    "metadata": {"risk": {"cvss_base_score": 0}},
                    "type": "wpscan_report",
                    "timestamp": timestamp,
                    "description": _parse_description(content["main_theme"]),
                }
            )
            nb_vulns[get_criticity(0)] += 1
            for vulnerability in content["main_theme"]["vulnerabilities"]:
                metadata = {"risk": {"cvss_base_score": 0}}
                if (
                    "references" in vulnerability
                    and "url" in vulnerability["references"]
                ):
                    metadata = {
                        "risk": {"cvss_base_score": 0},
                        "links": vulnerability["references"]["url"],
                    }
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(8),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "Theme {} vulnerability: {}".format(
                            content["main_theme"]["slug"], vulnerability["title"]
                        ).rstrip(),
                        "solution": "n/a",
                        "metadata": metadata,
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(vulnerability),
                    }
                )
                nb_vulns[get_criticity(8)] += 1
            for parent in content["main_theme"]["parents"]:
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(0),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "Theme: {}".format(parent["slug"]).rstrip(),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}},
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(parent),
                    }
                )
                nb_vulns[get_criticity(0)] += 1
                for vulnerability in parent["vulnerabilities"]:
                    metadata = {"risk": {"cvss_base_score": 0}}
                    if (
                        "references" in vulnerability
                        and "url" in vulnerability["references"]
                    ):
                        metadata = {
                            "risk": {"cvss_base_score": 0},
                            "links": vulnerability["references"]["url"],
                        }
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": get_criticity(8),
                            "confidence": "certain",
                            "target": {
                                "addr": [asset],
                                "protocol": "http",
                                "parent": asset,
                            },
                            "title": "Theme {} vulnerability: {}".format(
                                parent["slug"], vulnerability["title"]
                            ).rstrip(),
                            "solution": "n/a",
                            "metadata": metadata,
                            "type": "wpscan_report",
                            "timestamp": timestamp,
                            "description": _parse_description(vulnerability),
                        }
                    )
                    nb_vulns[get_criticity(8)] += 1

        # Plugins
        if "plugins" in content and content["plugins"]:
            for plugin_name in content["plugins"]:
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(0),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "Plugin: {}".format(plugin_name).rstrip(),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}},
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(
                            content["plugins"][plugin_name]
                        ),
                    }
                )
                nb_vulns[get_criticity(0)] += 1
                for vulnerability in content["plugins"][plugin_name]["vulnerabilities"]:
                    metadata = {"risk": {"cvss_base_score": 0}}
                    if (
                        "references" in vulnerability
                        and "url" in vulnerability["references"]
                    ):
                        metadata = {
                            "risk": {"cvss_base_score": 0},
                            "links": vulnerability["references"]["url"],
                        }
                    issues.append(
                        {
                            "issue_id": len(issues) + 1,
                            "severity": get_criticity(8),
                            "confidence": "certain",
                            "target": {
                                "addr": [asset],
                                "protocol": "http",
                                "parent": asset,
                            },
                            "title": "Plugin {} vulnerability: {}".format(
                                plugin_name, vulnerability["title"]
                            ).rstrip(),
                            "solution": "n/a",
                            "metadata": metadata,
                            "type": "wpscan_report",
                            "timestamp": timestamp,
                            "description": _parse_description(vulnerability),
                        }
                    )
                    nb_vulns[get_criticity(8)] += 1

        # Users
        if "users" in content and content["users"]:
            for user_name in content["users"]:
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(0),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "User: {}".format(user_name).rstrip(),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}},
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(content["users"][user_name]),
                    }
                )
                nb_vulns[get_criticity(0)] += 1

        # Version
        if "version" in content and content["version"]:
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": get_criticity(0),
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "http", "parent": asset},
                    "title": "Version: {} [{}]".format(
                        content["version"]["number"], content["version"]["release_date"]
                    ).rstrip(),
                    "solution": "n/a",
                    "metadata": {"risk": {"cvss_base_score": 0}},
                    "type": "wpscan_report",
                    "timestamp": timestamp,
                    "description": _parse_description(content["version"]),
                }
            )
            nb_vulns[get_criticity(0)] += 1
            if (
                "status" in content["version"]
                and content["version"]["status"] != "latest"
            ):
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(5),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "Version {} [{}] is {}".format(
                            content["version"]["number"],
                            content["version"]["release_date"],
                            content["version"]["status"],
                        ).rstrip(),
                        "solution": "n/a",
                        "metadata": {"risk": {"cvss_base_score": 0}},
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(content["version"]),
                    }
                )
                nb_vulns[get_criticity(5)] += 1
            for vulnerability in content["version"]["vulnerabilities"]:
                metadata = {"risk": {"cvss_base_score": 0}}
                if (
                    "references" in vulnerability
                    and "url" in vulnerability["references"]
                ):
                    metadata = {
                        "risk": {"cvss_base_score": 0},
                        "links": vulnerability["references"]["url"],
                    }
                issues.append(
                    {
                        "issue_id": len(issues) + 1,
                        "severity": get_criticity(8),
                        "confidence": "certain",
                        "target": {
                            "addr": [asset],
                            "protocol": "http",
                            "parent": asset,
                        },
                        "title": "Wordpress version {} vulnerability: {}".format(
                            content["version"]["number"], vulnerability["title"]
                        ).rstrip(),
                        "solution": "n/a",
                        "metadata": metadata,
                        "type": "wpscan_report",
                        "timestamp": timestamp,
                        "description": _parse_description(vulnerability),
                    }
                )
                nb_vulns[get_criticity(8)] += 1

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "wpscan",
        "engine_version": engine.scanner["version"],
    }

    return issues, summary


@app.route("/engines/wpscan/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    """Get findings."""
    res = {"page": "getfindings", "scan_id": scan_id}
    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    # check if the scan is finished
    status()
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update(
            {"status": "error", "reason": "scan_id '{}' not finished".format(scan_id)}
        )
        return jsonify(res)

    has_error = False
    has_error_reason = ""
    for asset in engine.scans[scan_id]["reports"].keys():
        proc = engine.scans[scan_id]["reports"][asset]["proc"]
        if (
            hasattr(proc, "pid")
            and psutil.pid_exists(proc.pid)
            and psutil.Process(proc.pid).status() in ["sleeping", "running"]
        ):
            has_error = True
            has_error_reason = "Scan in progress"
            break

        # check if the report is available (exists && scan finished)
        if not exists(engine.scans[scan_id]["reports"][asset]["report_path"]):
            has_error = True
            has_error_reason = "Report file not available for asset {}".format(asset)
            break

        # Check if report is a valid json
        try:
            with open(
                engine.scans[scan_id]["reports"][asset]["report_path"], "r"
            ) as results_file:
                content = results_file.read()
            json.loads(content)
        except json.decoder.JSONDecodeError:
            has_error = True
            has_error_reason = "Report file is not a valid json"
            break
        except Exception:
            has_error = True
            has_error_reason = "Report file not readable"
            break

    if has_error is True:
        res.update({"status": "error", "reason": has_error_reason})
        return jsonify(res)

    issues, summary = _parse_results(scan_id)
    scan = {"scan_id": scan_id}

    # Store the findings in a file
    with open(
        APP_BASE_DIR + "/results/wpscan_" + scan_id + ".json", "w"
    ) as report_file:
        json.dump(
            {"scan": scan, "summary": summary, "issues": issues},
            report_file,
            default=_json_serial,
        )

    # remove the scan from the active scan list
    clean_scan(scan_id)

    res.update(
        {"scan": scan, "summary": summary, "issues": issues, "status": "success"}
    )
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not exists(APP_BASE_DIR + "/results"):
        os.makedirs(APP_BASE_DIR + "/results")
    _loadconfig()
    LOG.debug("Run engine")


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
