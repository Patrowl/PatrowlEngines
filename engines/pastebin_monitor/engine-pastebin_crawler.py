#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
PastebinMonitor Crawler

MIT License

Copyright (c) 2020 Yann Faure - Leboncoin
'''

import os
import re
import json
import time
import datetime
import logging
import multiprocessing as mp

import urllib3

from classes.database import Database
from classes.crawler import Crawler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
database = Database('database.db')

crawler = Crawler(logging)

APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SCRAPPED_URLS = []

def find_assets(link):
    '''Find assets'''
    if len(SCRAPPED_URLS) > 5000:
        SCRAPPED_URLS.clear()

    html_source = crawler.get_source(link)
    assets = database.fetchall('SELECT id, asset, criticity from patrowl_assets')
    for asset in assets:
        criticity = asset[2]
        search = re.findall(f"{asset.lower()}", html_source.lower())
        if len(search) > 0:
            data = database.fetchall('SELECT id from findings WHERE link = ?', (link,))
            if not data:
                logging.info(f"ALERT FOUND ON: {link} / Criticity: {criticity}")
                logging.info(f"=== Content: ===\r\n{html_source}")

                database.exec('INSERT INTO findings(asset, link, content, criticity, \
                            is_new, date_found, date_updated) \
                            VALUES (?, ?, ?, ?, ?, ?, ?);',
                            (asset, link, html_source, criticity, 1,
                            datetime.datetime.now(), datetime.datetime.now(),))
    SCRAPPED_URLS.append(link)

def crawl_ideone():
    '''Crawl ideone.com'''
    src = crawler.get_source('https://ideone.com/recent')
    data = src.findAll('div', attrs={'class': 'header'})
    for section in data:
        data = section.findAll('a')
        for link in data:
            link = 'https://ideone.com/plain' + link['href']
            if '/recent/' not in link:
                if not any(link in s for s in SCRAPPED_URLS):
                    find_assets(link)

def crawl_kpaste():
    '''Crawl kpaste.net'''
    src = crawler.get_source('https://kpaste.net/')
    data = src.find('div', attrs={'class': 'p'}).findAll('a')
    print(data)
    for link in data:
        link = link['href']
        if link != '/':
            link = 'https://kpaste.net' + link
            if not any(link in s for s in SCRAPPED_URLS):
                find_assets(link)

def crawl_codepad():
    '''Crawl codepad.org'''
    src = crawler.get_source('http://codepad.org/recent')
    data = src.findAll('div', attrs={'class': 'section'})
    for section in data:
        link = section.findAll('table')[1].find('a')['href']
        if not any(link in s for s in SCRAPPED_URLS):
            find_assets(link)

def crawl_github():
    '''Crawl gist.github.com'''
    for i in range(1, 8):
        src = crawler.get_source('https://gist.github.com/discover?page={}'.format(i))
        data = src.findAll('a', attrs={'class': 'link-overlay'})
        for link in data:
            link = link['href']
            if not any(link in s for s in SCRAPPED_URLS):
                find_assets(link)

def crawl_slexy():
    '''Crawl slexy.org'''
    src = crawler.get_source('https://slexy.org/recent')
    data = src.find('table').findAll('a')
    for link in data:
        if link['href'] != '/recent':
            link = 'https://slexy.org' + link['href']
            if not any(link in s for s in SCRAPPED_URLS):
                find_assets(link)

def crawl_pastebin_fr():
    '''Crawl pastebin.fr'''
    src = crawler.get_source('http://pastebin.fr/')
    data = src.find('ol').findAll('a')
    for link in data:
        download_link = 'http://pastebin.fr/pastebin.php?dl={}' \
                        .format(link['href']
                        .replace('http://pastebin.fr/', ''))
        if not any(link['href'] in s for s in SCRAPPED_URLS):
            find_assets(download_link)

def crawl_pastebin_com_with_api_key():
    '''Crawl pastebin.com with an api key each hour'''
    while True:
        try:
            src = crawler.get_source('https://scrape.pastebin.com/api_scraping.php')
            data = json.loads(str(src))
            for item in data:
                link = item['scrape_url']
                if not any(item['full_url'] in s for s in SCRAPPED_URLS):
                    find_assets(link)
            time.sleep(300)
        except Exception as ex:
            logging.debug(ex)

def crawl_pastes():
    '''Crawling main function'''
    while True:
        try:
            crawl_ideone()
            crawl_kpaste()
            crawl_codepad()
            crawl_github()
            crawl_slexy()
            crawl_pastebin_fr()
            time.sleep(200)
        except Exception as ex:
            logging.debug(ex)

def init_database():
    '''Init the database and create tables if not exists'''
    database.exec('CREATE TABLE IF NOT EXISTS patrowl_assets \
                (id INTEGER PRIMARY KEY, asset TEXT NOT NULL, criticity TEXT NOT NULL);')
    database.exec('CREATE TABLE IF NOT EXISTS findings \
                (id INTEGER PRIMARY KEY, asset TEXT NOT NULL, \
                link TEXT NOT NULL, content TEXT NOT NULL, \
                criticity TEXT NOT NULL, is_new INTEGER NOT NULL, \
                date_found DATETIME NOT NULL, date_updated DATETIME NOT NULL);')

def init_config():
    '''Init the config file'''
    with open('pastebin_monitor.json') as json_file:
        return json.load(json_file)

if __name__ == '__main__':
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")

    init_database()

    config = init_config()

    apikey = config['options']['ApiKey']['value']

    cpu_count = mp.cpu_count()
    pool = mp.Pool(processes = cpu_count)
    '''Crawl pastebin.com in a different thread with the api key'''
    pool.apply_async(crawl_pastes)

    if len(apikey) > 0:
        pool.apply_async(crawl_pastebin_com_with_api_key())

    pool.close()
    pool.join()
