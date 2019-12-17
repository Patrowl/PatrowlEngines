#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
PastebinMonitor PatrOwl engine to crawl pastebin with or without API key with a proxy list.
'''

import os
import re
import sys
import random
import json
import time
import sqlite3
import logging
from sys import argv
from multiprocessing import Pool
from flask import Flask, request, jsonify, redirect, url_for
from bs4 import BeautifulSoup
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)

APP_DEBUG = False
APP_HOST = '0.0.0.0'
APP_PORT = 5020
APP_MAXSCANS = 5
APP_ENGINE_NAME = 'pastebin_monitor'
APP_DBNAME = 'database.db'
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))

SESSION = requests.Session()

app = Flask(__name__)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

SCRAPPED_URLS = []

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

@app.route('/engines/pastebin_monitor/status')
def status():
    '''Get status on engine and all scans.'''
    res = {'page': 'status', 'status': 'UNKNOWN'}
    if len(engine.scans) == APP_MAXSCANS:
        engine.scanner['status'] = "BUSY"
    else:
        engine.scanner['status'] = "READY"

    scans = []
    for scan_id in engine.scans.keys():
        status_scan(scan_id)
        scans.append({scan_id: {
            "status": engine.scans[scan_id]['status'],
            "started_at": engine.scans[scan_id]['started_at'],
            "assets": engine.scans[scan_id]['assets']
        }})

    res.update({
        "nb_scans": len(engine.scans),
        "status": engine.scanner['status'],
        "scanner": engine.scanner,
        "scans": scans})
    return jsonify(res)

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

    data = sql_fetchall('SELECT id, asset, link, content, criticity FROM findings')

    issues = []

    for row in data:
        issues.append({
            "issue_id": len(issues)+1,
            "severity": row[4], "confidence": "certain",
            "target": {"addr": [row[1]], "protocol": "http"},
            "title": "Asset found on: {}".format(row[2]),
            "solution": "n/a",
            "metadata": {"risk": {"criticity": row[4]}},
            "type": "pastebin_monitor_report",
            "timestamp": int(time.time() * 1000),
            "description": "The asset '{}' is available on this pastebin link: {}\n\nContent:\n\n{}"
                           .format(row[1], row[2], row[3]),
        })

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

    res.update({'scan': scan, 'summary': summary, 'issues': issues, 'status': 'success'})

    sql_exec('DELETE FROM findings;')

    return jsonify(res)

@app.route('/engines/pastebin_monitor/startscan', methods=['POST'])
def start_scan():
    '''Start a new scan.'''
    try:
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

    except(KeyboardInterrupt, SystemExit):
        sys.exit(0)

class PastebinCrawler:
    '''PastebinCrawler Class'''
    def find_assets(self, link, text):
        '''Find regexes in a pastebin post.'''
        if len(SCRAPPED_URLS) > 5000:
            SCRAPPED_URLS.clear()

        for asset, criticity in engine.scanner['assets'].items():
            if text is not None:
                parse = text.encode('utf-8').decode('utf-8')
                search = re.findall("{}".format(asset.lower()), parse.lower())
                if len(search) > 0:
                    data = sql_fetchall('SELECT id from findings WHERE link = ?', (link,))

                    if not data:
                        logging.info('ALERT FOUND ON: {} / Criticity: {}'.format(link, criticity))
                        logging.info('=== Content: ===\r\n{}'.format(text))

                        sql_exec('INSERT INTO findings(asset, link, content, criticity) \
                                     VALUES (?, ?, ?, ?);', (asset, link, text, criticity))
        SCRAPPED_URLS.append(link)

    def do_get_request(self, res):
        '''Perform GET request.'''
        try:
            logging.info('url: {}'.format(res['url']))
            with open('useragents.txt') as file:
                lines = file.readlines()
                line = random.choice(lines)
                line = line.replace('\r', '').replace('\n', '')
                data = SESSION.get(res['url'],
                                   headers={'user-agent': '{}'.format(line)},
                                   proxies=res['proxy'],
                                   verify=False,
                                   timeout=res['timeout'], allow_redirects=False)
                logging.debug(data)
                return data
        except requests.exceptions.ConnectTimeout:
            if res['proxy'] is not None:
                logging.debug("[{}] Failed to connect on: '{}' with {}"
                              .format(res['threadname'], res['url'], res['proxy']['http']
                                      .replace('http://', '')))
                self.get_random_proxy()
            else:
                logging.debug("[{}] Failed to connect on: '{}'"
                              .format(res['threadname'], res['url']))
        except requests.exceptions.ReadTimeout:
            if res['proxy'] is not None:
                logging.debug("[{}] Failed to connect on: '{}' with {}"
                              .format(res['threadname'], res['url'], res['proxy']['http']
                                      .replace('http://', '')))
                self.get_random_proxy()
            else:
                logging.debug("[{}] Failed to connect on: '{}'"
                              .format(res['threadname'], res['url']))
        except requests.exceptions.ProxyError:
            pass
        except requests.exceptions.ConnectionError:
            pass

    def get_random_proxy(self):
        '''Get random proxy from a text file.'''
        with open('proxies.txt') as file:
            lines = file.readlines()
            line = random.choice(lines)
            line = line.replace('\r', '').replace('\n', '')
            proxy = 'http://{}'.format(line)
            proxy_https = 'https://{}'.format(line)
            proxy = {'http': proxy, 'https': proxy_https}
            return proxy

    def connect_proxy(self, res):
        '''Use a proxy for pastebin.'''
        data = requests.Response()
        while data is None or data.status_code != 200:
            proxy = self.get_random_proxy()
            res.update({'proxy': proxy})
            data = self.do_get_request(res)
        return data

CRAWL = PastebinCrawler()

def get_source(url):
    '''Get soup object from a resource'''
    logging.debug('Checking {}'.format(url))
    res = {'threadname': 'MainThread', 'url': url, 'proxy': None,
           'timeout': 3, 'last_index': None}
    data = CRAWL.do_get_request(res)
    return {'res': res, 'soup': BeautifulSoup(data.text, 'html.parser')}

def crawl_pastebin_com_with_api_key():
    '''Crawl pastebin.com with an API key.'''
    while True:
        res = {'threadname': 'MainThread', 'url': 'https://scrape.pastebin.com/api_scraping.php',
               'proxy': None, 'timeout': 3, 'last_index': None}

        data = CRAWL.do_get_request(res)
        for item in json.loads(data.text):
            res.update({'url': item['scrape_url']})
            if not any(res['url'] in s for s in SCRAPPED_URLS):
                data = CRAWL.do_get_request(res)
                if data is not None:
                    CRAWL.find_assets(item['full_url'], data.text)
                time.sleep(2)
        time.sleep(2)

def crawl_pastebin_fr():
    '''Crawl pastebin.fr'''
    while True:
        src = get_source('http://pastebin.fr/')
        data = src['soup'].find('ol').findAll('a')

        for link in data:
            download_url = 'http://pastebin.fr/pastebin.php?dl={}' \
                            .format(link['href']
                                    .replace('http://pastebin.fr/', ''))
            src['res'].update({'url': download_url})
            if not any(link['href'] in s for s in SCRAPPED_URLS):
                data = CRAWL.do_get_request(src['res'])
                CRAWL.find_assets(download_url, data.text)
                time.sleep(2)
        time.sleep(20)

def crawl_slexy_org():
    '''Crawl slexy.org'''
    while True:
        src = get_source('https://slexy.org/recent')
        data = src['soup'].find('table').findAll('a')
        for link in data:
            if link['href'] != '/recent':
                link = 'https://slexy.org' + link['href']

                if not any(link in s for s in SCRAPPED_URLS):
                    src = get_source(link)
                    data = src['soup'].find('div', attrs={'class': 'text'})
                    CRAWL.find_assets(link, data)
                    time.sleep(2)
        time.sleep(20)

def crawl_gists_github_com():
    '''Crawl gist.github.com'''
    while True:
        src = get_source('https://gist.github.com/discover')
        data = src['soup'].findAll('a', attrs={'class': 'link-overlay'})
        for link in data:
            link = link['href']
            if not any(link in s for s in SCRAPPED_URLS):
                src['res'].update({'url': link})
                data = CRAWL.do_get_request(src['res'])
                CRAWL.find_assets(link, data.text)
                time.sleep(2)
        time.sleep(20)

def crawl_codepad_org():
    '''Crawl codepad.org'''
    while True:
        src = get_source('http://codepad.org/recent')
        sections = src['soup'].findAll('div', attrs={'class': 'section'})
        for section in sections:
            link = section.findAll('table')[1].find('a')['href']
            if not any(link in s for s in SCRAPPED_URLS):
                src['res'].update({'url': link})
                data = CRAWL.do_get_request(src['res'])
                CRAWL.find_assets(link, data.text)
                time.sleep(2)
        time.sleep(20)

def crawl_kpaste_net():
    '''Crawl kpaste.net'''
    while True:
        src = get_source('https://kpaste.net/')
        data = src['soup'].find('div', attrs={'class': 'p'}).findAll('a')
        for link in data:
            link = link['href']
            if link != '/':
                link = 'https://kpaste.net' + link
                if not any(link in s for s in SCRAPPED_URLS):
                    src['res'].update({'url': link})
                    data = CRAWL.do_get_request(src['res'])
                    CRAWL.find_assets(link, data.text)
                    time.sleep(2)
        time.sleep(20)

def crawl_ideone_com():
    '''Crawl ideone.com'''
    while True:
        src = get_source('https://ideone.com/recent')
        data = src['soup'].find('div', attrs={'class': 'span8'}).findAll('a')
        for link in data:
            link = 'https://ideone.com/plain' + link['href']
            if '/recent/' not in link:
                if not any(link in s for s in SCRAPPED_URLS):
                    src['res'].update({'url': link})
                    data = CRAWL.do_get_request(src['res'])
                    CRAWL.find_assets(link, data.text)
                    time.sleep(2)
        time.sleep(20)

def crawl_pastebin_com_without_api_key(threadname):
    '''Crawl pastebin.com without an API key.'''
    res = {'threadname': threadname, 'url': 'https://pastebin.com/', 'proxy': None,
           'timeout': 3, 'last_index': None}
    while True:
        logging.info('[{}] Starting a scan on: ({})'.format(res['threadname'], res['url']))

        if res['proxy'] is None:
            data = CRAWL.connect_proxy(res)
        else:
            data = CRAWL.do_get_request(res)

        if data is None:
            return

        soup = BeautifulSoup(data.text, 'html.parser')
        data = soup.findAll('ul', attrs={'class': 'right_menu'})

        for node in data:
            links = node.findAll('a')
            if res['last_index'] is None:
                res['last_index'] = links[0]

            for i, link in enumerate(links):
                link = '{}raw{}'.format(res['url'], link['href'])
                if i != 0 and links[i] == res['last_index']:
                    logging.info('[{}] Already scanned link: {}'.format(threadname, link))
                    res['last_index'] = links[i-1]
                    break

                if not any(link in s for s in SCRAPPED_URLS):
                    res.update({'url': link})
                    logging.info('[{}] {} ({})'
                                 .format(res['threadname'], link, res['proxy']))
                    data = CRAWL.do_get_request(res)
                    while data is None or 'Pastebin.com has blocked your IP' in data.text:
                        CRAWL.connect_proxy(res)
                        data = CRAWL.do_get_request(res)
                    CRAWL.find_assets(link, data.text)
                    time.sleep(1)

@app.route('/engines/pastebin_monitor/info')
def info():
    status()
    return jsonify({"page": "info", "engine_config": engine.scanner})

def _loadconfig():
    '''Load the Engine configuration.'''
    conf_file = APP_BASE_DIR+'/pastebin_monitor.json'
    if len(argv) > 1 and os.path.exists(APP_BASE_DIR+"/"+argv[1]):
        conf_file = APP_BASE_DIR + "/" + argv[1]
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
    if not os.path.exists(APP_BASE_DIR+'/results'):
        os.makedirs(APP_BASE_DIR+'/results')
    _loadconfig()

    sql_exec('CREATE TABLE IF NOT EXISTS findings \
                (id INTEGER PRIMARY KEY, asset TEXT NOT NULL, \
                link TEXT NOT NULL, content TEXT NOT NULL, \
                criticity TEXT NOT NULL);')

    POOL = Pool()

    if len(engine.scanner['options']['ApiKey']['value']) > 0:
        POOL.apply_async(crawl_pastebin_com_with_api_key)
    else:
        for i in range(engine.scanner['options']['ThreadsNumber']['value']):
            threadname = 'thread{}'.format(i)
            POOL.apply_async(crawl_pastebin_com_without_api_key, args=(threadname,))

    POOL.apply_async(crawl_pastebin_fr)
    POOL.apply_async(crawl_slexy_org)
    POOL.apply_async(crawl_gists_github_com)
    POOL.apply_async(crawl_codepad_org)
    POOL.apply_async(crawl_kpaste_net)
    POOL.apply_async(crawl_ideone_com)

    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
