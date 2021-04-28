"""
Cybel Angel Patrowl Engine

Copyright 2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""
import logging

import requests


class CybelAngel():
    _base_url = 'https://platform.cybelangel.com/api'
    _auth_url = 'https://auth.cybelangel.com/oauth/token'
    _default_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0'
    _access_token = ''

    def __init__(self, client_id, client_secret, user_agent=None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._user_agent = self._default_user_agent
        if user_agent:
            self._user_agent = user_agent
        self._logger = logging.getLogger(__name__)
        self._set_headers()

    def _set_headers(self):
        self._headers = {
            'User-Agent': self._user_agent,
            'Authorization': f'Bearer {self._access_token}'
        }

    def get_token(self):
        '''Get access_token to use API
        '''
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'audience': 'https://platform.cybelangel.com/',
            'grant_type': 'client_credentials'
        }
        resp = requests.post(self._auth_url, headers=self._headers, json=data)
        if resp.status_code != 200:
            self._logger.error(f'Unable to get token: {resp.status_code = } | {resp.text = }')
            return False
        self._access_token = resp.json()['access_token']
        self._set_headers()
        return resp.json()['access_token']

    def get_open_reports(self):
        '''Get reports
        '''
        url = f'{self._base_url}/v1/reports?status=open'
        i = 0
        done = False
        reports = []
        while not done:
            resp = requests.get(f'{url}&skip={i * 10}', headers=self._headers)
            if resp.status_code != 200:
                self._logger.error(f'Unable to get reports: {resp.status_code = } | {resp.text = }')
                return False
            reports += resp.json()['reports']
            if len(resp.json()['reports']) < 10:
                done = True
            i += 1
        return reports

    def resolve_report(self, report_id):
        url = f'{self._base_url}/v1/reports/{report_id}/status'
        data = {
            'status': 'resolved'
        }
        resp = requests.put(url, headers=self._headers, json=data)
        if resp.status_code != 200:
            self._logger.error(f'Unable to update report {report_id}: {resp.status_code = } | {resp.text = }')
            return False
        return True

    def process(self):
        if not self.get_token():
            return False
        if not (reports := self.get_open_reports()):
            return False
        reports_malicious_website = list()
        for report in reports:
            if report['category'] == 'dns' and report['incident_type'] == 'malicious_website':
                reports_malicious_website.append(report)
        return reports_malicious_website
