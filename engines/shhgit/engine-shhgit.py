#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHHGIT PatrOwl engine application

Copyright (C) 2021 Nicolas Mattiocco - @MaKyOtOx
Licensed under the AGPLv3 License
Written by Fabien Martinez (fabien.martinez@adevinta.com)
"""

import os
import sys
import json
import time
import logging
import threading
from pathlib import Path
from hashlib import sha256
import shutil

from flask import Flask, request, jsonify
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

from libs.github import get_github_repositories
from libs.git_leaks import clone_repository, get_leaks_from_repository


app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5025
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 1))
APP_ENGINE_NAME = "shhgit"
APP_BASE_DIR = Path(__file__).parent
DATA_BASE_PATH = APP_BASE_DIR / 'data'
REPO_BASE_PATH = DATA_BASE_PATH / 'repositories'
OUTPUT_BASE_PATH = DATA_BASE_PATH / 'results'

VERSION = "1.2.0"

logging.basicConfig(level=(logging.DEBUG if APP_DEBUG else logging.INFO))
LOGGER = logging.getLogger('shhgit')

engine = PatrowlEngine(
    app=app,
    base_dir=str(APP_BASE_DIR.absolute()),
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)

this = sys.modules[__name__]
this.keys = []


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


@app.route('/')
def default():
    """Route by default."""
    return engine.default()


@app.route('/engines/shhgit/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/shhgit/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/shhgit/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/shhgit/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/shhgit/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/shhgit/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/shhgit/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/shhgit/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/shhgit/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    res.update({'status': engine.scans[scan_id]['status']})

    return jsonify(res)


@app.route('/engines/shhgit/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/shhgit/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/shhgit/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    """Load configuration file."""
    conf_file = APP_BASE_DIR / 'shhgit.json'
    global LOGGER
    try:
        json_data = conf_file.read_text()
    except FileNotFoundError:
        LOGGER.error(f'Unable to find config file "{conf_file.absolute()}"')
        return {"status": "error", "reason": "config file not found"}
    except Exception as e:
        LOGGER.error(f'Unable to read config file "{conf_file.absolute()}": {e}')
        return {"status": "error", "reason": "unable to read config file"}
    else:
        try:
            engine.scanner = json.loads(json_data)
        except Exception as e:
            LOGGER.error(f'Unable to convert config file to json: {e}')
            return {"status": "error", "reason": "unable to convert config file to json"}
        else:
           engine.scanner['status'] = 'READY'
        if 'options' not in engine.scanner or "github_accounts" not in engine.scanner['options']:
            LOGGER.error("Unable to find options in config file")
            return {"status": "error", "reason": "you have to specify options in your config file"}
        if 'logger' in engine.scanner['options']:
            LOGGER = logging.getLogger(engine.scanner['options']['logger'])
        required_keys = ['base_url', 'github_key', 'is_internal', 'patrowl_group', 'organization']
        for github_group in engine.scanner['options']['github_accounts']:
            if not isinstance(github_group, dict):
                LOGGER.error('Malformed github_group')
                return {'status': 'error', 'reason': 'you have to define valid github_accounts'}
            for required_key in required_keys:
                if required_key not in github_group:
                    LOGGER.error('Malformed github_group')
                    return {'status': 'error', 'reason': 'you have to define valid github_accounts'}

    version_filename = APP_BASE_DIR / 'VERSION'
    if version_filename.exists():
        engine.version = version_filename.read_text().rstrip('\n')


@app.route('/engines/shhgit/reloadconfig', methods=['GET'])
def reloadconfig():
    res = {"page": "reloadconfig"}
    resp = _loadconfig()
    if resp:
        res.update(resp)
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route('/engines/shhgit/startscan', methods=['POST'])
def start_scan():
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": f"Scan refused: max concurrent active scans reached ({APP_MAXSCANS})"
        })

        return jsonify(res)

    status()
    if engine.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": engine.scanner['status']
            }})
        return jsonify(res)

    data = json.loads(request.data)
    scan_id = str(data['scan_id'])

    if data['scan_id'] in engine.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "scan '{}' already launched".format(data['scan_id']),
            }
        })
        return jsonify(res)

    scan = {
        'threads':      [],
        'options':      data['options'],
        'scan_id':      scan_id,
        'status':       "STARTED",
        'started_at':   int(time.time() * 1000),
        'findings':     [],
        'assets':       []
    }

    engine.scans.update({scan_id: scan})
    thread = threading.Thread(target=check_repositories, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]['threads'].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan['scan_id']
        }
    })

    return jsonify(res)


def check_repositories(scan_id):
    repositories_to_check = []
    for github_account in engine.scanner['options']['github_accounts']:
        repositories = get_github_repositories(github_account)
        if not repositories:
            continue
        else:
            repositories_to_check.append({
                'github_token': github_account['github_key'],
                'group_name': github_account['patrowl_group'],
                'repositories': repositories
            })
        LOGGER.info(f'Repositories found for {github_account["patrowl_group"]}: {len(repositories)}')
    engine.scans[scan_id]['output_paths'] = {}
    for data in repositories_to_check:
        LOGGER.info(f'group name: {data["group_name"]}')
        output_path = OUTPUT_BASE_PATH / github_account['patrowl_group']
        if not output_path.exists():
            try:
                output_path.mkdir(parents=True)
            except Exception as e:
                LOGGER.error(f'Unable to create directory {output_path.absolute()}: {e}')
                engine.scans[scan_id]['status'] = 'ERROR'
                return False
        if github_account['patrowl_group'] not in engine.scans[scan_id]['output_paths']:
            engine.scans[scan_id]['output_paths'][github_account['patrowl_group']] = []
        for repository in data['repositories']:
            repository_path = clone_repository(
                repository['clone_url'],
                repository['name'],
                data['github_token'],
                REPO_BASE_PATH
            )
            if not repository_path:
                continue
            leaks = get_leaks_from_repository(
                repository_path,
                output_path / f'{repository["name"]}_{repository["id"]}.json'
            )
            try:
                shutil.rmtree(repository_path)
            except Exception as e:
                LOGGER.error(f'Unable to remove repository {repository_path}: {e}')
                continue
            if leaks:
                LOGGER.info(f'Number of leaks found for {repository["name"]}: {len(leaks)}')
                engine.scans[scan_id]['output_paths'][github_account['patrowl_group']].append({
                    'repository_name': repository['name'],
                    'output_path': output_path / f'{repository["name"]}_{repository["id"]}.json'
                })
    engine.scans[scan_id]['status'] = 'FINISHED'
    engine.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    if REPO_BASE_PATH.exists():
        try:
            shutil.rmtree(REPO_BASE_PATH)
        except Exception as e:
            LOGGER.error(f'Unable to remove {REPO_BASE_PATH.absolute()}/*: {e}')
    return True


def get_report(asset, scan_id):
    """Get report."""
    result = dict()
    result_file = APP_BASE_DIR / 'results' / f'shhgit_{scan_id}.json'
    try:
        result = json.loads(result_file.read_text())
        result_file.close()
    except Exception:
        return {"status": "ERROR", "reason": "no issues found"}

    return result


def hashcode(key):
    mod = sha256()
    mod.update(key)
    return mod.hexdigest()[:8]


def _parse_results(scan_id):
    issues = []
    summary = {}
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }
    for patrowl_group, output_paths in engine.scans[scan_id]['output_paths'].items():
        for repository_data in output_paths:
            timestamp = int(time.time() * 1000)
            try:
                raw_issues = json.loads(repository_data['output_path'].read_text())
            except Exception as e:
                LOGGER.error(f'Unable to get issues from {repository_data["output_path"].absolute()}: {e}')
                continue
            for raw_issue in raw_issues:
                nb_vulns[raw_issue['criticity']] += 1
                issues.append({
                    "issue_id": len(issues) + 1,
                    "severity": raw_issue['criticity'],
                    "confidence": "certain",
                    "target": {"addr": [repository_data['repository_name']], "protocol": "http", "parent": patrowl_group},
                    "title": f'{raw_issue["title"]} [{hashcode(raw_issue["reason"].encode("utf-8", "ignore"))}]',
                    "solution": "n/a",
                    "metadata": {"risk": {"criticity": raw_issue['criticity']}},
                    "type": "shhgit_report",
                    "timestamp": timestamp,
                    "description": f'Component: {raw_issue["component"]}\nReason: {raw_issue["reason"]}'
                })

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "engine_name": "shhgit",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route('/engines/shhgit/getfindings/<scan_id>', methods=['GET'])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    if engine.scans[scan_id]['status'] != "FINISHED":
        res.update({"status": "error", "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]['status'])})
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "options": engine.scans[scan_id]['options'],
        "status": engine.scans[scan_id]['status'],
        "started_at": engine.scans[scan_id]['started_at'],
        "finished_at": engine.scans[scan_id]['finished_at']
    }

    # Store the findings in a file
    report_file = APP_BASE_DIR / 'results' / f'shhgit_{scan_id}.json'
    try:
        report_file.write_text(json.dumps({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, default=_json_serial))
    except Exception as e:
        LOGGER.error(f'Unable to write in {report_file.absolute()}: {e}')
        res.update({"status": "error", "reason": "unable to write in report file"})
    else:
        res.update({"scan": scan, "summary": summary, "issues": issues, "status": "success"})
    finally:
        # remove the scan from the active scan list
        clean_scan(scan_id)
        return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    result_path = APP_BASE_DIR / 'results'
    if not result_path.exists():
        result_path.mkdir(parents=True)
    _loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
