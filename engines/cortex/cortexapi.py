#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import magic
import requests
from future.utils import raise_from


class InvalidInputException(Exception):
    pass


class CortexException(Exception):
    pass


class CortexApi:
    """
        Python API for Cortex

        :param url: Cortex URL
        :param apikey: Cortex API Key
        :param proxies: dict object defining URLs of http and https proxies
    """

    def __init__(self, url, apikey, proxies={}, cert=True):
        """
        An client for the REST APIs defined by Cortex

        Args:
            :param url:
            :param apikey:
            :param proxies (:obj:`dict`, optional): An object defining the http/https proxy URLs.
                Should have two attributes: `http` or `https` indicating the proxy's URL
            :param cert (``str``, optional): True by default to enable cert verification, False to disable it

        """

        self.url = url
        self.apikey = apikey
        self.headers = {'Authorization': 'Bearer {}'.format(self.apikey) }
        self.proxies = proxies
        self.cert = cert

    def __handle_error(self, exception):
        if isinstance(exception, requests.exceptions.ConnectionError):
            raise_from(CortexException("Cortex service is unavailable"), exception)
        elif isinstance(exception, requests.exceptions.RequestException):
            raise_from(CortexException("Cortex request exception"), exception)
        elif isinstance(exception, InvalidInputException):
            raise_from(CortexException("Invalid input exception"), exception)
        else:
            raise_from(CortexException("Unexpected exception"), exception)

    def get_analyzers(self, data_type=None):
        """
            Get the list of all analyzers or the analyzers that can run on the observables of type `data_type`

            :param data_type: Observable data type
            :type data_type: ``str``

            :return: A JSON array of analyzer objects
        """
        if data_type is not None:
            req = self.url + '/api/analyzer/type/{}'.format(str(data_type))
        else:
            req = self.url + '/api/analyzer'

        try:
            response = requests.get(req, proxies=self.proxies, verify=self.cert, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            else:
                self.__handle_error(CortexException(response.text))
        except Exception as e:
            self.__handle_error(e)

    def run_analyzer(self, analyzer_id, data_type, tlp, observable):
        """
            Call the REST API responsible of running a given analyzer on a given observable

            :param analyzer_id: The identifier of the analyzer
            :param data_type: The observable's data type
            :param tlp: The observable's TLP
            :param observable: The observable value or the file path if the observable is a File

            :type analyzer_id: ``str``
            :type data_type: ``str``
            :type tlp: ``integer``
            :type observable: ``str``

            :return: A JSON object describing a job
        """
        req = self.url + "/api/analyzer/{}/run".format(analyzer_id)

        if data_type == "file":
            file_def = {
                "data": (os.path.basename(observable), open(observable, 'rb'),
                         magic.Magic(mime=True).from_file(observable))
            }
            data = {
                "_json": json.dumps({
                    "dataType": "file",
                    "tlp": tlp
                })
            }
            try:
                response = requests.post(req, data=data, files=file_def, proxies=self.proxies, verify=self.cert, headers=self.headers)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 400:
                    self.__handle_error(InvalidInputException(response.text))
                else:
                    self.__handle_error(CortexException(response.text))
            except Exception as e:
                self.__handle_error(e)

        else:
            post = {
                "data": observable,
                "attributes": {
                    "dataType": data_type,
                    "tlp": tlp
                }
            }
            try:
                response = requests.post(req,
                                         headers={'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(self.apikey)},
                                         data=json.dumps(post),
                                         proxies=self.proxies,
                                         verify=self.cert)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 400:
                    self.__handle_error(InvalidInputException(response.text))
                else:
                    self.__handle_error(CortexException(response.text))
            except Exception as e:
                self.__handle_error(e)

    def get_job_report(self, job_id, timeout='Inf'):
        """
            Call the REST API returning the report of a job identified by the given `job_id`

            :param job_id: The job's identifier
            :param timeout: The wait duration using the format 30s, 10m, 1h

            :type job_id: ``str``
            :type timeout: ``str``

            :return: A JSON object describing a job report
        """
        req = self.url + '/api/job/{}/waitreport?atMost={}'.format(job_id, timeout)

        try:
            response = requests.get(req, proxies=self.proxies, verify=self.cert, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            else:
                self.__handle_error(CortexException(response.text))
        except requests.exceptions.RequestException as e:
            self.__handle_error(e)

    def delete_job(self, job_id):
        """
            Call the REST API that deletes the job identified by the given `job_id`

            :param job_id: The job's identifier

            :type job_id: ``str``

            :return: True if the deletion completes successfully
        """
        req = self.url + '/api/job/{}'.format(job_id)
        try:
            response = requests.delete(req, proxies=self.proxies, verify=self.cert, headers=self.headers)

            if response.status_code == 200:
                return True
            else:
                self.__handle_error(CortexException(response.text))
        except requests.exceptions.RequestException as e:
            self.__handle_error(e)
