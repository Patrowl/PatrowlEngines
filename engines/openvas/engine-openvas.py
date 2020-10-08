#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

import os
from os import makedirs
from os.path import dirname, exists, isfile, realpath
from sys import modules
from json import dump, load, loads
# from re import search as re_search
from netaddr import IPNetwork, IPAddress, glob_to_iprange
from netaddr.core import AddrFormatError
from threading import Thread
from time import time
from urllib.parse import urlparse
from uuid import UUID
import xml.etree.ElementTree as ET
import re
import hashlib
import validators

# Third party library imports
from flask import Flask, request, jsonify
from dns.resolver import query
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv7.types import AliveTest
# from gvm.errors import GvmError

# Own library
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = os.environ.get('APP_DEBUG', '').lower() in ['true', '1', 'on', 'yes']
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 5))
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = dirname(realpath(__file__))
DEFAULT_OV_PROFILE = "Full and fast"
DEFAULT_OV_PORTLIST = "patrowl-all_tcp"
DEFAULT_TIMEOUT = int(os.environ.get('DEFAULT_TIMEOUT', 600))

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

this = modules[__name__]
this.keys = []
this.gmp = None
this.openvas_portlists = {}

OV_ALIVE_TESTS = {
    "CONSIDER_ALIVE": "Consider Alive",
    "ICMP_TCP_ACK_SERVICE_AND_ARP_PING": "ICMP, TCP-ACK Service & ARP Ping",
    "TCP_ACK_SERVICE_AND_ARP_PING": "TCP-ACK Service & ARP Ping",
    "ICMP_AND_ARP_PING": "ICMP & ARP Ping",
    "ICMP_AND_TCP_ACK_SERVICE_PING": "ICMP & TCP-ACK Service Ping",
    "ARP_PING": "ARP Ping",
    "TCP_ACK_SERVICE_PING": "TCP-ACK Service Ping",
    "TCP_SYN_SERVICE_PING": "TCP-SYN Service Ping",
    "ICMP_PING": "ICMP Ping",
    "DEFAULT": "Scan Config Default",
}


def is_uuid(uuid_string, version=4):
    """Check uuid_string is a valid UUID."""
    try:
        uid = UUID(uuid_string, version=version)
        return uid.hex == uuid_string.replace("-", "")
    except ValueError:
        return False


def get_options(payload):
    """Extract formatted options from the payload."""
    options = {"enable_create_target": True, "enable_create_task": True, "enable_start_task": True}
    user_opts = payload["options"]
    if "enable_create_target" in user_opts:
        options["enable_create_target"] = True or user_opts["enable_create_target"] == "True"
    if "enable_create_task" in user_opts:
        options["enable_create_task"] = True or user_opts["enable_create_task"] == "True"
    if "enable_start_task" in user_opts:
        options["enable_start_task"] = True or user_opts["enable_start_task"] == "True"
    return options


def get_target(target_name, scan_portlist_id=None, alive_test=None):
    """Return the target_id of a target. If not, it returns None."""
    valid_target_id = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        targets_xml = gmp_cnx.get_targets()
        # print("targets_xml:", targets_xml)
        try:
            targets = ET.fromstring(targets_xml)
        except Exception:
            return None
        if not targets.attrib["status"] == "200":
            return None

        for target in targets.findall("target"):
            # print("target:", target)
            if scan_portlist_id is None and target_name in target.find("name").text:
                valid_target_id = target.get("id")
                if not is_uuid(valid_target_id):
                    valid_target_id = None
            elif scan_portlist_id == target.find("port_list").get('id') and target_name in target.find("name").text:
                valid_target_id = target.get("id")
                if not is_uuid(valid_target_id):
                    valid_target_id = None

    connection.disconnect()
    return valid_target_id


# def get_credentials(name=None):
#     """Return the credentials_id from conf (or None)."""
#
#     # result_xml = this.gmp.get_credentials()
#     connection = TLSConnection(
#         hostname=engine.scanner["options"]["gmp_host"]["value"],
#         port=engine.scanner["options"]["gmp_port"]["value"],
#         timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
#     )
#     with Gmp(connection) as gmp_cnx:
#         gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
#         result_xml = gmp_cnx.get_credentials()
#         try:
#             result = ET.fromstring(result_xml)
#         except Exception:
#             return None
#         if not result.attrib["status"] == "200":
#             return None
#
#         creds_name = name
#         if name is None:
#             # Set the default value set in engine config
#             creds_name = engine.scanner["options"]["default_credential_name"]["value"]
#
#         for credential in result.findall("credential"):
#             if credential.find("name").text == creds_name:
#                 credentials_id = credential.attrib["id"]
#                 if not is_uuid(credentials_id):
#                     return None
#                 return credentials_id
#     return None


def get_scan_config_name(scan_config_id=None, gmp=this.gmp):
    scan_config_name = None
    configs_xml = gmp.get_configs()
    try:
        configs = ET.fromstring(configs_xml)
    except Exception:
        return None

    for config in configs.findall('config'):
        if config.get("id") == scan_config_id:
            scan_config_name = config.find("name").text
            break

    if scan_config_name is None:
        return engine.scanner["options"]["default_scan_config_name"]["value"]
    else:
        return scan_config_name


def get_scan_config(name=None):
    """Return the scan_config_id from conf."""
    # print("in get_scan_config(name={})".format(name))

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        configs_xml = gmp_cnx.get_configs()
        # print("configs_xml:", configs_xml)
        try:
            configs = ET.fromstring(configs_xml)
        except Exception as e:
            print(e)
            return None

        # print("get_scan_config-configs:", configs)

        scan_config_name = name
        if name is None:
            # Set the default value set in engine config
            scan_config_name = get_scan_config_name(gmp=gmp_cnx)
        # print("get_scan_config-scan_config_name:", scan_config_name)

        for config in configs.findall("config"):
            tmp_config_name = config.find("name").text
            # print("get_scan_config-loop-tmp_config_name", tmp_config_name)
            if scan_config_name == tmp_config_name:
                scan_config_id = config.get("id")
                if not is_uuid(scan_config_id, version=1) and not is_uuid(scan_config_id):
                    return None
                return scan_config_id
        return None
    connection.disconnect()


def create_target(
    target_name,
    target_hosts,
    port_list_id=None,
    port_list_name=None,
    ssh_credential_id=None, ssh_credential_port=None,
    smb_credential_id=None,
    esxi_credential_id=None,
    snmp_credential_id=None,
    alive_test=AliveTest.TCP_SYN_SERVICE_PING):
    """Create a target in OpenVAS and returns its target_id."""
    # app.logger.debug(
    #     "create_target(): {}, {}, {}, {}",
    #     target_name, port_list_id, port_list_name, alive_test)

    # Check alive_test param
    if alive_test not in OV_ALIVE_TESTS.keys():
        alive_test = AliveTest.TCP_SYN_SERVICE_PING
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        new_target_xml = gmp_cnx.create_target(
            "{} - {} - {}".format(target_name, port_list_name, alive_test),
            # hosts=[target_name],
            hosts=target_hosts,
            ssh_credential_id=ssh_credential_id,
            ssh_credential_port=ssh_credential_port,
            smb_credential_id=smb_credential_id,
            esxi_credential_id=esxi_credential_id,
            snmp_credential_id=snmp_credential_id,
            port_list_id=port_list_id,
            # alive_test=OV_ALIVE_TESTS[alive_test]
            alive_test=alive_test
        )
        # print("new_target_xml:", new_target_xml)
        try:
            new_target = ET.fromstring(new_target_xml)
        except Exception as e:
            print(e)
            app.logger.error(e)
            target_id = None
        if not new_target.get("status") == "201":
            target_id = None
        target_id = new_target.get("id")
        if not is_uuid(target_id):
            target_id = None

    connection.disconnect()
    return target_id


def get_task_by_target_name(target_name, scan_config_id=None):
    """Return the task_id."""

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        tasks_xml = gmp_cnx.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg")
        target_id = get_target(target_name)
        if target_id is None:
            return None
        try:
            tasks = ET.fromstring(tasks_xml)
        except Exception:
            return None
        if not tasks.get("status") == "200":
            return None

        for task in tasks.findall("task"):
            if task.find('target').get("id") == target_id and task.find('config').get('id') == scan_config_id:
                task_id = task.get("id")
                if not is_uuid(task_id):
                    return None
                connection.disconnect()
                return task_id

    connection.disconnect()
    return None


def get_scanners(name=None):
    """Return the list of scanners' ID."""
    scanners_list = []
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        scanners_xml = gmp_cnx.get_scanners()
        try:
            scanners = ET.fromstring(scanners_xml)
        except Exception:
            return None
        if not scanners.get("status") == "200":
            return None

        for scanner in scanners.findall("scanner"):
            if name is not None:
                if name == scanner.find('name').text:
                    return [scanner.get("id")]
            else:
                scanners_list.append(scanner.get("id"))

    connection.disconnect()
    return scanners_list


def create_task(target_name, target_id, scan_config_id=None, scanner_id=None):
    """Create a task_id in OpenVAS and returns its task_id."""
    if scan_config_id is None:
        scan_config_id = get_scan_config()  # Set the default value
    if scanner_id is None:
        scanner_id = get_scanners()[1]  # Set the default value

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        new_task_xml = gmp_cnx.create_task(
            name=target_name + " - {}".format(get_scan_config_name(scan_config_id, gmp=gmp_cnx)),
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        try:
            new_task = ET.fromstring(new_task_xml)
        except Exception:
            return None
        if not new_task.get("status") == "201":
            return None

        task_id = new_task.get("id")
        if not is_uuid(task_id):
            return None
        connection.disconnect()
        return task_id


def start_task(task_id):
    """Start a task and returns a report_id."""
    # print("in start_task(task_id={})".format(task_id))
    report_id = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        start_scan_results_xml = gmp_cnx.start_task(task_id)
        # print("start_scan_results_xml:", start_scan_results_xml)
        try:
            start_scan_results = ET.fromstring(start_scan_results_xml)
            # print("start_scan_results:", start_scan_results)
        except Exception as e:
            print(e)
            connection.disconnect()
            return None
        if start_scan_results.get("status") != "202":
            # print("bad start_scan_results")
            connection.disconnect()
            return None

        # if start_scan_results.get("status") == "400":
        #     report_id = get_last_report(task_id)
        # else:
        report_id = start_scan_results.find("report_id").text
        if report_id == "0" or not is_uuid(report_id):
            report_id = None
    # print("report_id:", report_id)
    connection.disconnect()
    return report_id


def get_last_report(task_id):
    """Return the last report_id of a task_id."""
    last_report = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        task_xml = gmp_cnx.get_task(task_id)
        try:
            task = ET.fromstring(task_xml)
        except Exception:
            return None
        if not task.get("status") == "200":
            return None

        try:
            last_report = task.find("task").find("last_report").find("report")
        except Exception:
            connection.disconnect()
            return None
        if not is_uuid(last_report.get("id")):
            connection.disconnect()
            return None
        connection.disconnect()
        return last_report.get("id")

#
# def get_report_status(report_id):
#     """Get the status of a report_id."""
#     connection = TLSConnection(
#         hostname=engine.scanner["options"]["gmp_host"]["value"],
#         port=engine.scanner["options"]["gmp_port"]["value"],
#         timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
#     )
#     with Gmp(connection) as gmp_cnx:
#         gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
#         # report_status_xml = this.gmp.get_report(report_id, filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg")
#         report_status_xml = gmp_cnx.get_report(report_id, filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg")
#         try:
#             report_status = ET.fromstring(report_status_xml)
#         except Exception:
#             return None
#         if not report_status.get("status") == "200":
#             return None
#
#         return report_status.find("report").find("report").find("scan_run_status").text


def get_multiple_report_status(info, gmp_cnx):
    """
    Get the status of a set of assets
    {'task_id': xx, 'report_id': xx}.
    """
    assets_status = dict()
    result_xml = gmp_cnx.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1")
    try:
        result = ET.fromstring(result_xml)
    except Exception:
        return None
    if not result.attrib["status"] == "200":
        return None

    if "task_id" not in info.keys() or "report_id" not in info.keys():
        return None
    task_id = info["task_id"]
    report_id = info["report_id"]
    report = result.find("task/[@id='{task_id}']/*/report[@id='{report_id}']".format(
        task_id=task_id, report_id=report_id))
    if report is None:
        assets_status.update({"status": "Failure"})
    else:
        scan_end = report.find("scan_end").text
        if scan_end is None:
            assets_status.update({"status": "Running"})
        else:
            assets_status.update({"status": "Done"})

    return assets_status


def is_domain(string):
    """Return True is the string is probably a domain."""
    res = False
    try:
        res = validators.domain(string)
    except Exception:
        pass
    return res


def is_ip(string):
    """Return True is the string is probably an IP."""
    try:
        IPAddress(string)
    except Exception:
        return False
    return True


def is_ip_subnet(subnet):
    try:
        IPNetwork(subnet)
    except (TypeError, ValueError, AddrFormatError):
        return False
    if "/" not in subnet:
        return False
    return True


def subnet_ips(subnet):
    ips = []
    if is_ip_subnet(subnet):
        try:
            ips = [str(ip) for ip in IPNetwork(subnet)]
        except Exception:
            return ips
    return ips


def is_ip_range(subnet):
    ips = []
    try:
        ips = glob_to_iprange(subnet)
    except Exception:
        return []
    return ips


def range_ips(range):
    ips = []
    if is_ip_range(range):
        ips = [str(ip) for ip in glob_to_iprange(range)]
    return ips


def split_port(asset_port):
    port_number = "0"
    port_protocol = "tcp"
    try:
        if asset_port.split('/')[0].isnumeric():
            port_number = asset_port.split('/')[0]

        if asset_port.split('/')[1] in ["tcp", "udp"]:
            port_protocol = asset_port.split('/')[1]
    except Exception:
        pass
    return port_number, port_protocol


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


@app.route("/")
def default():
    """Route by default."""
    return engine.default()


@app.route("/engines/openvas/")
def index():
    """Return index page."""
    return engine.index()


@app.route("/engines/openvas/liveness")
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route("/engines/openvas/readiness")
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route("/engines/openvas/test")
def test():
    """Return test page."""
    return engine.test()


@app.route("/engines/openvas/info")
def info():
    """Get info on running engine."""
    # return engine.info()
    status()
    return jsonify({
        "page": "info",
        "engine_config": {
            "name": engine.name,
            "description": engine.description,
            "version": engine.version,
            "status": engine.status,
            "reason": engine.scanner.get("reason", ""),
            "allowed_asset_types": engine.allowed_asset_types,
            "max_scans": engine.max_scans,
            "nb_scans": len(engine.scans.keys()),
        }
    })


@app.route("/engines/openvas/clean")
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route("/engines/openvas/clean/<scan_id>")
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route("/engines/openvas/status")
def status():
    """Get status on engine and all scans."""
    res = {"page": "status"}

    if engine.status != "ERROR":
        if len(engine.scans) == engine.max_scans:
            engine.status = "BUSY"
        else:
            engine.status = "READY"

    scans = []
    for scan_id in engine.scans.keys():
        assets_map = None
        if "assets_map" in engine.scans[scan_id].keys():
            assets_map = engine.scans[scan_id]['assets_map']
        scans.append({scan_id: {
            "status": engine.scans[scan_id]['status'],
            "started_at": engine.scans[scan_id]['started_at'],
            "finished_at": engine.scans[scan_id]['finished_at'],
            "assets": engine.scans[scan_id]['assets'],
            "assets_map": assets_map
        }})

    res.update({
        "nb_scans": len(engine.scans),
        "status": engine.status,
        "scans": scans})
    return jsonify(res)


def _status_scan(scan_id, gmp_cnx):
    scan_status = "SCANNING"
    if engine.scans[scan_id]['status'] == "STARTED":
        return scan_status

    scan_assets_status = get_multiple_report_status(engine.scans[scan_id]["info"], gmp_cnx)
    if scan_assets_status is None:
        scan_status = "UNKNOWN"
        engine.scans[scan_id]['status'] = scan_status
        return scan_status

    if scan_assets_status["status"] == "Done":
        scan_status = "FINISHED"
        engine.scans[scan_id]["finished_at"] = int(time() * 1000)

    engine.scans[scan_id]['status'] = scan_status

    return scan_assets_status


@app.route("/engines/openvas/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": engine.scans[scan_id]["reason"]})
        return jsonify(res)

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])

        assets_status = _status_scan(scan_id, gmp_cnx)
        if engine.scans[scan_id]['status'] in ["SCANNING", "STARTED", "FINISHED"]:
            res.update({'status': engine.scans[scan_id]['status']})
            # return jsonify(res)

        # assets_status = get_multiple_report_status(engine.scans[scan_id]["info"], gmp_cnx)
        if assets_status is None:
            res.update({"status": "error", "reason": "Cannot find any report_status"})

    connection.disconnect()
    return jsonify(res)


@app.route("/engines/openvas/stopscans")
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route("/engines/openvas/stop/<scan_id>")
def stop_scan(scan_id):
    """Stop scan identified by id."""
    res = {"page": "stop_scan", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    task_id = engine.scans[scan_id]['info']['task_id']
    try:
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
        )
        with Gmp(connection) as gmp_cnx:
            gmp_cnx.authenticate(
                engine.scanner["options"]["gmp_username"]["value"],
                engine.scanner["options"]["gmp_password"]["value"])
            gmp_cnx.stop_task(task_id)
        connection.disconnect()
    except Exception:
        app.logger.debug("Unable to stop scan '{}'".format(scan_id))
    return engine.stop_scan(scan_id)


@app.route("/engines/openvas/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


@app.route("/engines/openvas/resetcnx")
def resetcnx():
    res = {"page": "resetcnx", "status": "success"}
    # try:
    #     this.gmp.finish_send()
    # except Exception:
    #     pass
    #
    # try:
    #     this.gmp.disconnect()
    # except Exception:
    #     pass
    #
    # try:
    #     connection = TLSConnection(
    #         hostname=engine.scanner["options"]["gmp_host"]["value"],
    #         port=engine.scanner["options"]["gmp_port"]["value"],
    #         timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    #     )
    #     with Gmp(connection) as this.gmp:
    #         this.gmp.authenticate(
    #             engine.scanner["options"]["gmp_username"]["value"],
    #             engine.scanner["options"]["gmp_password"]["value"])
    #     print("Gmp connection successfully reset.")
    #     app.logger.info("Gmp connection successfully reset.")
    # except Exception as ex:
    #     engine.scanner["status"] = "ERROR"
    #     engine.status = "ERROR"
    #
    #     if(ex.__str__() == "timed out"):
    #         engine.scanner["reason"] = "connection to {}:{} timed-out".format(connection.hostname, connection.port)
    #     else:
    #         engine.scanner["reason"] = ex.__str__()
    #
    #     res.update({"status": "error", "reason": engine.scanner["reason"]})
    #
    #     app.logger.error("Error: "+ex.__str__())
    return jsonify(res)


def _loadconfig():
    conf_file = APP_BASE_DIR+"/openvas.json"
    if not exists(conf_file):
        app.logger.error("Error: config file '{}' not found".format(conf_file))
        return False

    json_data = open(conf_file)
    engine.scanner = load(json_data)
    engine.scanner["status"] = "ERROR"
    engine.scanner["reason"] = "loadconfig error"

    try:
        response = ""
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
        )
        with Gmp(connection) as this.gmp:
            response = this.gmp.authenticate(
                engine.scanner["options"]["gmp_username"]["value"],
                engine.scanner["options"]["gmp_password"]["value"])
    except Exception as ex:
        engine.scanner["status"] = "ERROR"
        engine.status = "ERROR"

        if(ex.__str__() == "timed out"):
            engine.scanner["reason"] = "connection to {}:{} timed-out".format(connection.hostname, connection.port)
        else:
            engine.scanner["reason"] = ex.__str__()

        app.logger.error("Error: "+ex.__str__())
        return False

    # Check login response
    if response.find("authenticate_response status=\"400\"") > 0:
        engine.status = "ERROR"
        engine.scanner["status"] = "ERROR"
        engine.scanner["reason"] = "openvas login failed"
        return False

    # Check port lists
    try:
        portlists = ET.fromstring(this.gmp.get_port_lists())
    except Exception:
        return None
    for pl in portlists.findall('port_list'):
        pl_name = pl.find('name').text
        pl_uuid = pl.get('id')
        this.openvas_portlists.update({pl_name: pl_uuid})

    # Create custom port lists
    if "patrowl-all_tcp" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-all_tcp",
                port_range="T:1-65535"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-all_tcp": new_pl.get('id')})
        except Exception:
            return None

    if "patrowl-quick_tcp" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-quick_tcp",
                port_range="T:21-80,T:443,U:53"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-quick_tcp": new_pl.get('id')})
        except Exception:
            return None

    if "patrowl-tcp_80" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_80",
                port_range="T:80"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_80": new_pl.get('id')})
        except Exception:
            return None

    if "patrowl-tcp_443" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_443",
                port_range="T:443"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_443": new_pl.get('id')})
        except Exception:
            return None

    if "patrowl-tcp_22" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_22",
                port_range="T:22"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_22": new_pl.get('id')})
        except Exception:
            return None

    engine.scanner["status"] = "READY"
    engine.scanner["credentials"] = ()
    this.gmp.disconnect()


@app.route("/engines/openvas/reloadconfig", methods=["GET"])
def reloadconfig():
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/openvas/startscan", methods=["POST"])
def start_scan():
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update({
            "status": "error",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)

    status()
    if engine.scanner["status"] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": engine.scanner.get("reason", "scanner not ready"),
                "status": engine.scanner["status"]
            }})
        return jsonify(res)

    data = loads(request.data.decode("utf-8"))
    if "assets" not in data.keys() or "scan_id" not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update({
                "status": "error",
                "reason": "arg error, something is missing ('asset.value')"
            })
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update({
                "status": "error",
                "reason": "arg error, bad value for '{}' datatype (not supported)".format(asset["value"])
            })
            return jsonify(res)

        if asset["datatype"] == "url":
            parsed_uri = urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    scan = {
        "assets":       assets,
        "threads":      [],
        "options":      data["options"],
        "scan_id":      scan_id,
        "status":       "STARTED",
        "reason":       "",
        "lock":         False,
        "started_at":   int(time() * 1000),
        "finished_at":  "",
        "findings":     {}
    }

    engine.scans.update({scan_id: scan})
    thread = Thread(target=_scan_assets, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]["threads"].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan["scan_id"]
        }
    })

    return jsonify(res)


def _scan_assets(scan_id):
    scan = engine.scans[scan_id]
    # print("scan:", engine.scans[scan_id])

    scan_config_name = None
    if 'profile' in engine.scans[scan_id]["options"].keys():
        scan_config_name = engine.scans[scan_id]["options"]["profile"]
    # print("scan_config_name:", scan_config_name)

    scan_config_id = get_scan_config(name=scan_config_name)
    # print("scan_config_id:", scan_config_id)
    scan_portlist_id = this.openvas_portlists["OpenVAS Default"]
    scan_portlist_name = ""
    if 'port_list' in scan["options"].keys():
        scan_portlist_name = scan["options"]["port_list"]
        if scan_portlist_name in this.openvas_portlists.keys():
            scan_portlist_id = this.openvas_portlists[scan_portlist_name]
    # print("scan_portlist_id:", scan_portlist_id)

    options = get_options(scan)
    # print(options)

    # engine.scans[scan_id]["assets"] = dict()
    # print('engine.scans[scan_id]["assets"]:', engine.scans[scan_id]["assets"])
    # for asset in engine.scans[scan_id]["assets"]:
    #     print("asset:", asset)
    assets = engine.scans[scan_id]["assets"]
    assets_hash = hashlib.sha1(str(''.join(assets)).encode('utf-8')).hexdigest()
    engine.scans[scan_id]["assets_hash"] = assets_hash

    try:
        target_id = get_target(assets_hash, scan_portlist_id)
        # print("asset:", asset, "target_id-after-get_target:", target_id)
        # print("asset:", asset, 'options["enable_create_target"]', options["enable_create_target"])
        if target_id is None and options["enable_create_target"] is True:
            # print("Go create target for asset:", asset)
            target_id = create_target(
                target_name=assets_hash,
                target_hosts=engine.scans[scan_id]["assets"],
                port_list_id=scan_portlist_id,
                port_list_name=scan_portlist_name)  # Todo: add credentials if needed
        # print("asset:", asset, "target_id-after-create_target:", target_id)
        if target_id is None:
            engine.scans[scan_id]['status'] = "ERROR"
            engine.scans[scan_id]['reason'] = "Unable to create a target ({})".format(assets_hash)

        # print("target_id", target_id)
        task_id = get_task_by_target_name(assets_hash, scan_config_id)
        if task_id is None and options["enable_create_task"] is True:
            task_id = create_task(assets_hash, target_id, scan_config_id=scan_config_id)
        if task_id is None:
            engine.scans[scan_id]['status'] = "ERROR"
            engine.scans[scan_id]['reason'] = "Unable to create a task ({})".format(assets_hash)
        # print("task_id", task_id)

        if options["enable_start_task"] is True:
            report_id = start_task(task_id)
            if report_id is None:
                report_id = get_last_report(task_id)
        else:
            report_id = get_last_report(task_id)
        # print(asset, "report_id", report_id)

        if report_id is None:
            engine.scans[scan_id]['status'] = "ERROR"
            engine.scans[scan_id]['reason'] = "Unable to get a report ({})".format(assets_hash)

        # Store the scan info
        engine.scans[scan_id]['info'] = {
                "task_id": task_id,
                "report_id": report_id,
                "status": "accepted"
            }
    except Exception as e:
        print(e)
        engine.scans[scan_id]['status'] = "ERROR"
        engine.scans[scan_id]['reason'] = "Error when trying to start the scan"
        return False

    engine.scans[scan_id]['status'] = "SCANNING"
    return True


def get_report(scan_id):
    """Get report."""
    report_id = engine.scans[scan_id]["info"]["report_id"]
    # print("get_report()-report_id:", report_id)
    issues = []

    assets_hash = engine.scans[scan_id]["assets_hash"]
    # print("get_report()-assets_hash:", assets_hash)

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT))
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(engine.scanner["options"]["gmp_username"]["value"], engine.scanner["options"]["gmp_password"]["value"])
        if not isfile("results/openvas_report_{}_{}.xml".format(scan_id, assets_hash)):
            # rr = gmp_cnx.get_report_formats(report_id, filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg")
            # print(rr)

            result = gmp_cnx.get_report(report_id, filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg", details=1, ignore_pagination=1)
            result_file = open("results/openvas_report_{}_{}.xml".format(scan_id, assets_hash), "w")
            result_file.write(result)
            result_file.close()

        try:
            tree = ET.parse("results/openvas_report_{}_{}.xml".format(scan_id, assets_hash))
        except Exception as e:
            # No Element found in XML file
            app.logger.error(e)
            connection.disconnect()
            return {"status": "ERROR", "reason": "no issues found"}

        # Build the asset mapping
        assets_map = {}
        for asset in engine.scans[scan_id]['assets']:
            asset_datatype = "fqdn"
            siblings = [asset]
            if is_domain(asset):
                asset_datatype = "domain"
                # siblings.append(asset)
            elif is_ip(asset):
                asset_datatype = "ip"
                # siblings.append(asset)
            elif is_ip_subnet(asset):
                asset_datatype = "ip-subnet"
                siblings += subnet_ips(asset)
            elif is_ip_range(asset):
                asset_datatype = "ip-range"
                siblings += range_ips(asset)
            else:
                # Let's suppose it's a fqdn then...
                try:
                    records = query(asset).response.answer[0].items
                    for record in records:
                        # resolved_asset_ips.append(record.address)
                        siblings.append(record.address)
                except Exception as e:
                    # What is that thing ?
                    app.logger.error(e)
                    pass

            assets_map.update({
                asset: {
                    'siblings': list(set(siblings)),
                    'datatype': asset_datatype,
                    'has_issues': False
                }
            })
        print("assets_map:", assets_map)
        engine.scans[scan_id]['assets_map'] = assets_map

        report = tree.getroot().find("report")
        for result in report.findall('.//result'):
            # print(ET.tostring(result, encoding='utf8', method='xml'))
            try:
                host_ip = result.find("host").text
                host_name = result.find("host").find("hostname")
                # print("host_ip:", host_ip)
                for a in assets_map.keys():
                    if host_ip in assets_map[a]['siblings']:
                        issues.append(result)
                        engine.scans[scan_id]['assets_map'][a]['has_issues'] = True
                    elif host_name is not None and host_name.text in assets_map[a]['siblings']:
                        issues.append(result)
                        engine.scans[scan_id]['assets_map'][a]['has_issues'] = True
                # if host_ip in resolved_asset_ips:
                #     issues.append(result)
            except Exception as e:
                # probably unknown issue's host, skip it
                app.logger.error("Warning: failed to process issue: {}".format(ET.tostring(result, encoding='utf8', method='xml')))
                app.logger.error(e)

    print("engine.scans[scan_id]['assets_map']:", engine.scans[scan_id]['assets_map'])
    connection.disconnect()
    return issues


def _parse_results(scan_id):
    issues = []
    summary = {}

    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    timestamp = int(time() * 1000)

    # No issue
    if engine.scans[scan_id]["findings"] == {}:
        for asset in engine.scans[scan_id]['assets']:
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "tcp"
                },
                "title": "No results found.",
                "solution": "n/a",
                "metadata": {},
                "type": "openvas_report",
                "timestamp": timestamp,
                "description": "No results found during the scan.",
            })

    for asset in engine.scans[scan_id]['assets_map'].keys():
        if engine.scans[scan_id]['assets_map'][asset]['has_issues'] is False:
            issues.append({
                "issue_id": len(issues)+1,
                "severity": "info", "confidence": "certain",
                "target": {
                    "addr": [asset],
                    "protocol": "tcp"
                },
                "title": "No results found.",
                "solution": "n/a",
                "metadata": {},
                "type": "openvas_report",
                "timestamp": timestamp,
                "description": "No results found during the scan.",
            })

    titles = []
    for result in engine.scans[scan_id]["findings"]:
        # print("_parse_results/result", ET.tostring(result, encoding='utf8', method='xml'))
        try:
            # Do not report an outdated or end-of-life scan engine
            if "Report outdated" in result.find("nvt").find("name").text:
                continue
            if "Important Announcement" in result.find("nvt").find("name").text:
                continue

            severity = float(result.find("severity").text)
            # print("severity:", severity)
            cve = "NOCVE"
            if result.find("nvt").find("cve") is not None:
                cve = result.find("nvt").find("cve").text
            threat = result.find("threat").text
            cvss_base = result.find("nvt").find("cvss_base").text
            name = result.find("nvt").find("name").text
            tags = result.find("nvt").find("tags").text
            xmlDesc = result.find("description").text
            asset_port = result.find("port").text
            asset_port_number, asset_port_protocol = split_port(asset_port)
            solution = "n/a"
            title = "{port} - {name}".format(port=asset_port, name=name)

            # Remove duplicates
            if title not in titles:
                titles.append(title)
            else:
                continue

            asset_name = result.find("host").text
            asset_hostname = result.find("host").find("hostname")
            asset_names = []
            for a in engine.scans[scan_id]['assets_map'].keys():
                if asset_name in engine.scans[scan_id]['assets_map'][a]['siblings']:
                    if engine.scans[scan_id]['assets_map'][a]['datatype'] in ['ip-range', 'ip-subnet']:
                        asset_names.append(asset_name)
                    else:
                        asset_names.append(a)
                        # asset_names += engine.scans[scan_id]['assets_map'][a]['siblings']

                if asset_hostname is not None and asset_hostname.text in engine.scans[scan_id]['assets_map'][a]['siblings']:
                    asset_names.append(asset_hostname.text).append(asset_name)

            if len(asset_names) == 0:
                asset_names = [asset_name]

            # Remove duplicates
            asset_names = list(set(asset_names))

            # print("asset_names:", asset_names)

            if name == "Services":
                name = "Services - {}".format(xmlDesc)

            if severity >= 0:
                # form criticity
                criticity = "high"
                if severity == 0:
                    criticity = "info"
                elif severity < 4.0:
                    criticity = "low"
                elif severity < 7.0:
                    criticity = "medium"

            # update vulns counters
            nb_vulns[criticity] += 1

            # form description
            description = "[{threat}] CVSS: {severity} - Associated CVE: {cve}".format(
                threat=threat,
                severity=severity,
                cve=cve) + "\n\n"

            if (xmlDesc):
                description += xmlDesc + "\n\n"
            if (tags):
                description += tags.replace('|', '\n') + "\n\n"

            # Solution
            solution_data = re.search('\|solution=(.+?)\|', tags)
            if solution_data and solution_data[0] != "|":
                solution = solution_data.group(1)

            #  metadata
            finding_metadata = {
                "risk": {"cvss_base_score": cvss_base},
                "vuln_refs": {}
            }
            # CVE
            if cve != "NOCVE":
                finding_metadata.update({
                    "vuln_refs": {"CVE": [cve]}
                })

            # CPE
            try:
                if name == "CPE Inventory":
                    finding_metadata.update({
                        "vuln_refs": {"CPE": [c.split("|")[1] for c in xmlDesc.split("\n")]}
                    })
            except Exception:
                pass

            try:
                if name == "CPE Inventory":
                    finding_metadata.update({
                        "vuln_refs": {"CPE": [c.split("|")[1] for c in xmlDesc.split("\n\n")]}
                    })
            except Exception:
                pass

            # if (xmlDesc) and "CPE:" in str(xmlDesc):
            #     print(xmlDesc)
                # cpe_list = finding_metadata["vuln_refs"]["CPE"]
                # for desc_line in xmlDesc.split("\n"):
                #     if desc_line.startswith("CPE:"):
                #         cpe_list.append(desc_line.split("\t")[1])
                #
                # finding_metadata.update({
                #     "vuln_refs": {"CPE": cpe_list}
                # })

            # create issue
            issues.append({
                "issue_id": len(issues)+1,
                "severity": criticity, "confidence": "certain",
                "target": {
                    "addr": asset_names,
                    "protocol": asset_port_protocol
                },
                "title": title,
                "solution": solution,
                "metadata": finding_metadata,
                "type": "openvas_report",
                "timestamp": timestamp,
                "description": description,
            })
            # print("new_issue", issues[-1])

            xmlDesc = ""

        except Exception as e:
            # probably unknown issue's host, skip it
            app.logger.error("Warning: failed to process issue: {}".format(ET.tostring(result, encoding='utf8', method='xml')))
            app.logger.error(e)

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "openvas",
        "engine_version": engine.scanner["version"]
    }

    return issues, summary


@app.route("/engines/openvas/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check if the scan is finished
    status()
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update({
            "status": "error",
            "reason": "scan_id '{}' not finished (status={})".format(scan_id, engine.scans[scan_id]["status"])
        })
        return jsonify(res)

    try:
        engine.scans[scan_id]["findings"] = get_report(scan_id)
    except Exception as e:
        print(e)
        res.update({
            "status": "error",
            "reason": "Unable to get findings from scan '{}'.".format(scan_id)
        })
        return jsonify(res)

    issues, summary = _parse_results(scan_id)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]["assets"],
        "options": engine.scans[scan_id]["options"],
        "status": engine.scans[scan_id]["status"],
        "started_at": engine.scans[scan_id]["started_at"],
        "finished_at": engine.scans[scan_id]["finished_at"]
    }

    # Store the findings in a file
    with open(APP_BASE_DIR+"/results/openvas_"+scan_id+".json", "w") as rf:
        dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, rf, default=_json_serial)

    # Remove the scan from the active scan list
    clean_scan(scan_id)

    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"
    })
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not exists(APP_BASE_DIR+"/results"):
        makedirs(APP_BASE_DIR+"/results")
    _loadconfig()
    # resetcnx()
#
#
# @app.errorhandler(GvmError)
# def handle_gvm_error(e):
#     print("GvmError detected. Reset GVM connection")
#     resetcnx()
#     return 'bad request!', 400


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
