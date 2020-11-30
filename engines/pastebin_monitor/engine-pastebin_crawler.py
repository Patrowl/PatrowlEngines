#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
PastebinMonitor Crawler
'''

import os
import sys
import re
import json
import random
import time
import datetime
import sqlite3
import logging
import multiprocessing as mp

from bs4 import BeautifulSoup

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)

APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
APP_DBNAME = 'database.db'

SESSION = requests.Session()

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

def loadconfig():
    try:
        '''Load the Engine configuration.'''
        conf_file = APP_BASE_DIR+'/pastebin_monitor.json'
        if len(sys.argv) > 1 and os.path.exists(APP_BASE_DIR+"/"+sys.argv[1]):
            conf_file = APP_BASE_DIR + "/" + sys.argv[1]
        if os.path.exists(conf_file):
            json_data = open(conf_file)
            CONF = json.load(json_data)
            CONF["status"] = "READY"
            return CONF
        return {"status": "error", "reason": "config file not found"}
    except Exception as ex:
        logging.info(ex)

class PastebinCrawler:
    '''PastebinCrawler Class'''
    def find_assets(self, link, text):
        '''Find regexes in a pastebin post.'''
        CONF = loadconfig()

        if len(SCRAPPED_URLS) > 5000:
            SCRAPPED_URLS.clear()

        for asset, criticity in CONF['assets'].items():
            if text is not None:
                parse = text.encode('utf-8').decode('utf-8')
                search = re.findall("{}".format(asset.lower()), parse.lower())
                if len(search) > 0:
                    data = sql_fetchall('SELECT id from findings WHERE link = ?', (link,))

                    if not data:
                        logging.info('ALERT FOUND ON: {} / Criticity: {}'.format(link, criticity))
                        logging.info('=== Content: ===\r\n{}'.format(text))

                        sql_exec('INSERT INTO findings(asset, link, content, criticity, is_new, date_found, date_updated) \
                                     VALUES (?, ?, ?, ?, ?, ?, ?);', (asset, link, text, criticity, 1, datetime.datetime.now(), datetime.datetime.now(),))
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

def crawl_pastes():
    while True:
        try:
            '''Crawl ideone.com'''
            '''
            src = get_source('https://ideone.com/recent')
            data = src['soup'].find('div', attrs={'class': 'span8'}).findAll('a')
            for link in data:
                link = 'https://ideone.com/plain' + link['href']
                if '/recent/' not in link:
                    if not any(link in s for s in SCRAPPED_URLS):
                        src['res'].update({'url': link})
                        data = CRAWL.do_get_request(src['res'])
                        CRAWL.find_assets(link, data.text)
            '''

            '''Crawl kpaste.net'''
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

            '''Crawl codepad.org'''
            src = get_source('http://codepad.org/recent')
            sections = src['soup'].findAll('div', attrs={'class': 'section'})
            for section in sections:
                link = section.findAll('table')[1].find('a')['href']
                if not any(link in s for s in SCRAPPED_URLS):
                    src['res'].update({'url': link})
                    data = CRAWL.do_get_request(src['res'])
                    CRAWL.find_assets(link, data.text)
            
            '''Crawl gist.github.com'''
            for i in range(1, 8):
                src = get_source('https://gist.github.com/discover?page={}'.format(i))
                data = src['soup'].findAll('a', attrs={'class': 'link-overlay'})
                for link in data:
                    link = link['href']
                    if not any(link in s for s in SCRAPPED_URLS):
                        src['res'].update({'url': link})
                        data = CRAWL.do_get_request(src['res'])
                        CRAWL.find_assets(link, data.text)

            '''Crawl slexy.org'''
            src = get_source('https://slexy.org/recent')
            data = src['soup'].find('table').findAll('a')
            for link in data:
                if link['href'] != '/recent':
                    link = 'https://slexy.org' + link['href']
                    if not any(link in s for s in SCRAPPED_URLS):
                        src = get_source(link)
                        data = src['soup'].find('div', attrs={'class': 'text'})
                        CRAWL.find_assets(link, data)

            '''Crawl pastebin.fr'''
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

            time.sleep(240)
        except Exception as ex:
            logging.info(ex)

if __name__ == '__main__':
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")

    sql_exec('CREATE TABLE IF NOT EXISTS findings \
                (id INTEGER PRIMARY KEY, asset TEXT NOT NULL, \
                link TEXT NOT NULL, content TEXT NOT NULL, \
                criticity TEXT NOT NULL, is_new INTEGER NOT NULL, \
                date_found DATETIME NOT NULL, date_updated DATETIME NOT NULL);')

    cpu_count = mp.cpu_count()
    pool = mp.Pool(processes = cpu_count)
    pool.apply_async(crawl_pastes)
    pool.close()
    pool.join()
