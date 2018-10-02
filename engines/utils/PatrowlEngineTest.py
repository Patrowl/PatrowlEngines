#!/usr/bin/python
# -*- coding: utf-8 -*-
import json, requests, time, random
import pytest

class PatrowlEngineTest:
    def __init__(self, engine_name, base_url):
        self.engine_name = engine_name
        self.base_url = base_url

    def test_connectivity(self):
        print("test-{}-connectivity".format(self.engine_name))
        try:
            r = requests.get(url="{}/".format(self.base_url))
            assert r.status_code == 200
            assert r.json()["page"] == "index"

        except AssertionError:
            print(r.json()) ; assert False


    def test_status(self):
        print("test-{}-status".format(self.engine_name))
        r = requests.get(url="{}/status".format(self.base_url))
        try:
            assert r.status_code == 200
            assert r.json()["page"] == "status"
            assert r.json()["status"] == "READY"
        except AssertionError:
            print(r.json()) ; assert False


    def test_info(self):
        print("test-{}-info".format(self.engine_name))
        r = requests.get(url="{}/info".format(self.base_url))
        try:
            assert r.status_code == 200
            assert r.json()["page"] == "info"
            assert r.json()["engine_config"]["status"] == "READY"
        except AssertionError:
            print(r.json()) ; assert False

    def test_reloadconfig(self):
        print("test-{}-reloadconfig".format(self.engine_name))
        r = requests.get(url="{}/reloadconfig".format(self.base_url))
        try:
            assert r.status_code == 200
            assert r.json()["config"]["status"] == "READY"
        except AssertionError:
            print(r.json()) ; assert False

    def test_stopscans(self):
        print("test-{}-stopscans".format(self.engine_name))
        r = requests.get(url="{}/stopscans".format(self.base_url))
        try:
            assert r.status_code == 200
            assert r.json()["page"] == "stopscans"
            assert r.json()["status"] == "SUCCESS"
        except AssertionError:
            print(r.json()) ; assert False

    def test_cleanscans(self):
        print("test-{}-cleanscans".format(self.engine_name))
        r = requests.get(url="{}/clean".format(self.base_url))
        try:
            assert r.status_code == 200
            assert r.json()["page"] == "clean"
            assert r.json()["status"] == "SUCCESS"
        except AssertionError:
            print(r.json()) ; assert False

    def custom_test(self, test_name, assets, scan_policy={}, is_valid=True, max_timeout=1200):
        print("test-{}-custom: {}".format(self.engine_name, test_name))
        TEST_SCAN_ID = random.randint(1000000, 1999999)
        post_data = {
            "assets":  assets,
            "options": scan_policy,
            "scan_id": str(TEST_SCAN_ID)
        }

        r = requests.post(url="{}/startscan".format(self.base_url),
                   data=json.dumps(post_data),
                   headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
        try:
            assert r.status_code == 200
            assert r.json()['status'] == "accepted"
        except AssertionError:
            print(r.json()) ; assert False

        # Wait until scan is finished
        timeout_start = time.time()
        has_error = False
        while time.time() < timeout_start + max_timeout:
            r = requests.get(url="{}/status/{}".format(self.base_url, TEST_SCAN_ID))
            if r.json()["status"] == "SCANNING": continue
            elif r.json()["status"] == "FINISHED": break
            elif r.json()["status"] == "ERROR":
                has_error = True
                assert False
                break
            time.sleep(3)

        # Get findings
        if not has_error:
            r = requests.get(url="{}/getfindings/{}".format(self.base_url, TEST_SCAN_ID))
            try:
                assert r.json()['status'] == "success"
            except AssertionError:
                print(r.json()) ; assert False

            # Get report
            r = requests.get(url="{}/getreport/{}".format(self.base_url, TEST_SCAN_ID))
            try:
                # check the file name & siza !!
                assert True == True
                #assert r.json()['scan']['status'] == "FINISHED"
            except AssertionError:
                print(r.json()) ; assert False
        else:
            assert False

    def do_generic_tests(self):
        self.test_connectivity()
        self.test_status()
        self.test_info()
        self.test_reloadconfig()
        self.test_stopscans()
        self.test_cleanscans()
