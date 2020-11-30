#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
PastebinMonitor PatrOwl engine to crawl pastebin with or without API key with a proxy list.
'''

import os
import sys
import json
import time
import sqlite3
import datetime
import logging
from flask import Flask, request, jsonify, redirect, url_for
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

logging.basicConfig(level=logging.INFO)

APP_DEBUG = False
APP_HOST = '0.0.0.0'
APP_PORT = 3000
APP_MAXSCANS = 5
APP_ENGINE_NAME = 'pastebin_monitor'
APP_DBNAME = 'database.db'
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

def sql_exec(req, args=None):
    '''Execute a sql request'''
    conn = sqlite3.connect(APP_DBNAME)
    sql = conn.cursor()
    if args is None:
        sql.execute(req)
    else:
        sql.execute(req, args)
    conn.commit()
    conn.close()

def sql_fetchall(req, args=None):
    '''Execute a sql request and fetchall'''
    conn = sqlite3.connect(APP_DBNAME)
    sql = conn.cursor()
    if args is None:
        sql.execute(req)
    else:
        sql.execute(req, args)
    conn.commit()
    data = sql.fetchall()
    conn.close()
    return data

@app.errorhandler(404)
def page_not_found(error):
    '''Page not found.'''
    logging.debug(error)
    return engine.page_not_found()

@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    '''Invalid request usage.'''
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response

@app.route('/')
def default():
    return redirect(url_for('index'))

@app.route('/engines/pastebin_monitor/')
def index():
    return jsonify({"page": "index"})

@app.route('/engines/pastebin_monitor/liveness')
def liveness():
    return engine.liveness()

@app.route('/engines/pastebin_monitor/readiness')
def readiness():
    return engine.readiness()

@app.route('/engines/pastebin_monitor/test')
def test():
    return engine.test()

@app.route('/engines/pastebin_monitor/info')
def info():
    return engine.info()

@app.route('/engines/pastebin_monitor/clean')
def clean():
    return engine.clean()

@app.route('/engines/pastebin_monitor/clean/<scan_id>')
def clean_scan(scan_id):
    return engine.clean_scan(scan_id)

@app.route('/engines/pastebin_monitor/status')
def status():
    return engine.getstatus()

@app.route('/engines/pastebin_monitor/status/<scan_id>')
def status_scan(scan_id):
    '''Get status on scan identified by id.'''
    res = {'page': 'status', 'status': 'UNKNOWN'}

    if scan_id not in engine.scans.keys():
        res.update({'status': 'error', 'reason': "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    res.update({'status': 'FINISHED'})
    engine.scans[scan_id]['status'] = 'FINISHED'

    return jsonify(res)

@app.route('/engines/pastebin_monitor/stopscans')
def stop():
    return engine.stop()

@app.route('/engines/pastebin_monitor/stop/<scan_id>')
def stop_scan(scan_id):
    return engine.stop_scan(scan_id)

@app.route('/engines/pastebin_monitor/getreport/<scan_id>')
def getreport(scan_id):
    '''Get report on finished scans.'''
    res = {'status': 'ERROR', 'reason': 'no issues found'}

    if os.path.isfile('results/pastebin_monitor_report_{}.txt'.format(scan_id)):
        result_file = open('results/pastebin_monitor_report_{scan_id}.txt'
                           .format(scan_id=scan_id), 'r')
        result = result_file.read()
        result_file.close()
        return jsonify(result)
    return jsonify(res)

@app.route('/engines/pastebin_monitor/getfindings/<scan_id>')
def getfindings(scan_id):
    '''Get findings on finished scans.'''
    res = {'page': 'getfindings', 'scan_id': scan_id}

    data = sql_fetchall('SELECT id, asset, link, content, criticity, is_new, date_found, date_updated FROM findings')

    issues = []
    links = []

    for row in data:
        if row[5] == 1:
            links.append(row[2])
            issues.append({
                "issue_id": len(issues)+1,
                "severity": row[4], "confidence": "certain",
                "target": {"addr": [row[1]], "protocol": "http"},
                "title": "[Pastebin Crawler] Asset found on: {}".format(row[2]),
                "solution": "n/a",
                "metadata": {"risk": {"criticity": row[4]}, "links": links},
                "type": "pastebin_monitor_report",
                "timestamp": int(time.time() * 1000),
                "description": "[{}] The asset '{}' is available on this pastebin link: {}\n\nContent:\n\n{}"
                               .format(row[6], row[1], row[2], row[3]),
            })

            sql_exec('UPDATE findings SET is_new = ?, date_updated = ? WHERE id = ?', (0, datetime.datetime.now(), row[0]))

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]["assets"],
        "options": engine.scans[scan_id]["options"],
        "status": engine.scans[scan_id]["status"],
        "started_at": engine.scans[scan_id]["started_at"]
    }

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "pastebin_monitor"
    }

    if not os.path.isfile('results/pastebin_monitor_report_{}.txt'.format(scan_id)):
        result_file = open('results/pastebin_monitor_report_{}.txt'.format(scan_id), 'w')
        result_file.write(json.dumps({'scan': scan, 'summary': summary, 'issues': issues}))
        result_file.close()

    clean_scan(scan_id)

    res.update({'scan': scan, 'summary': summary, 'issues': issues, 'status': 'success'})

    return jsonify(res)

@app.route('/engines/pastebin_monitor/startscan', methods=['POST'])
def start_scan():
    '''Start a new scan.'''
    _loadconfig()
    res = engine.init_scan(request.data)

    if 'status' in res.keys() and res['status'] != 'INIT':
        return jsonify(res)

    scan_id = res['details']['scan_id']

    engine.scans[scan_id]['status'] = 'SCANNING'

    for asset in engine.scans[scan_id]['assets']:
        engine.scanner['assets'].update({asset['value']: asset['criticity']})

    file = open('pastebin_monitor.json', 'w')
    file.write(json.dumps(engine.scanner, indent=4))
    file.close()

    res.update({'status': 'accepted', 'details': {'scan_id': scan_id}})

    return jsonify(res)

def _loadconfig():
    '''Load the Engine configuration.'''
    conf_file = APP_BASE_DIR+'/pastebin_monitor.json'
    if len(sys.argv) > 1 and os.path.exists(APP_BASE_DIR+"/"+sys.argv[1]):
        conf_file = APP_BASE_DIR + "/" + sys.argv[1]
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        engine.scanner = json.load(json_data)
        engine.scanner["status"] = "READY"
        return {"status": "success"}
    return {"status": "error", "reason": "config file not found"}

@app.route('/engines/pastebin_monitor/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)

if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
