#!/usr/bin/python3
# -*- coding: utf-8 -*-
import validators
import socket
import json

def __is_ip_addr(host):
    res = False
    try:
        res = socket.gethostbyname(host) == host
    except Exception:
        pass
    return res


def __is_domain(host):
    res = False
    try:
        res = validators.domain(host)
    except Exception:
        pass
    return res


def json_validator(data):
    try:
        json.loads(data)
        return True
    except ValueError as error:
        print("invalid json: %s" % error)
