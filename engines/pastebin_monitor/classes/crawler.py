#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Crawler class

MIT License

Copyright (c) 2020 Yann Faure - Leboncoin
'''

import random
import requests
import urllib3

from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SESSION = requests.Session()

class Crawler():
    '''Crawler Class'''
    def __init__(self, logger, proxy = None, timeout = 5):
        self.logger = logger
        self.proxy = proxy
        self.timeout = timeout

    def get_random_user_agent(self):
        '''Geneate a random user agent from useragents.txt'''
        with open('useragents.txt') as file:
            line = random.choice(file.readlines())
            line = line.replace('\r', '').replace('\n', '')
            return line

    def get_random_proxy(self):
        '''Get a random proxy server from proxies.txt'''
        with open('proxies.txt') as file:
            line = random.choice(file.readlines())
            line = line.replace('\r', '').replace('\n', '')
            proxy_http = f"http://{line}"
            proxy_https = f"https://{line}"
            return {'http': proxy_http, 'https': proxy_https}

    def try_proxy(self):
        '''Try to connect to the proxy to test it'''
        data = requests.Response()
        while data is None or data.status_code != 200:
            proxy = self.get_random_proxy()
        return proxy

    def get_source(self, url):
        '''Get the html source on an html and beautify it with BeautifulSoup'''
        data = self.do_get_request(url)
        if data.text is not None:
            parse = data.text.encode('utf-8').decode('utf-8')
            return BeautifulSoup(parse, 'html.parser')
        return None

    def do_get_request(self, url):
        '''Perform GET request.'''
        try:
            self.logger.info(f"url: {url}")
            data = SESSION.get(url,
               headers={'user-agent': f"{self.get_random_user_agent()}"},
               proxies=self.proxy,
               verify=False,
               timeout=self.timeout, allow_redirects=False)
            return data
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            if self.proxy is not None:
                self.proxy = self.get_random_proxy()
            self.logger.debug(f"Failed to connect on: '{url}'")
        except requests.exceptions.ProxyError as ex:
            self.logger.debug(ex)
        except requests.exceptions.ConnectionError as ex:
            self.logger.debug(ex)
