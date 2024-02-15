#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

import os
from os import makedirs
from os.path import dirname, exists, isfile, realpath
from sys import modules
from json import dump, load, loads
from netaddr import IPNetwork, IPAddress, glob_to_iprange
from netaddr.core import AddrFormatError
from threading import Thread
import time
from urllib.parse import urlparse
from uuid import UUID
import xml.etree.ElementTree as ET
import re
import hashlib
import validators
import logging

# Third party library imports
from flask import Flask, request, jsonify
from dns.resolver import query
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

# from gvm.protocols.gmpv7.types import AliveTest
from gvm.protocols.gmpv208 import AliveTest

# from gvm.errors import GvmError

# Own library
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = os.environ.get("APP_DEBUG", "").lower() in ["true", "1", "on", "yes", "y"]
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = int(os.environ.get("APP_MAXSCANS", 5))
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = dirname(realpath(__file__))
# DEFAULT_OV_PROFILE = "Full and fast"
# DEFAULT_OV_PORTLIST = "patrowl-all_tcp"
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", 600))
DEFAULT_SCAN_TIMEOUT = int(os.environ.get("DEFAULT_SCAN_TIMEOUT", 432000))  # 2 days
VERSION = "1.4.30"

engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION,
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

if __name__ != "__main__":
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


def is_uuid(uuid_string, version=4):
    """Check uuid_string is a valid UUID."""
    try:
        uid = UUID(uuid_string, version=version)
        return uid.hex == uuid_string.replace("-", "")
    except ValueError:
        return False


def get_options(payload):
    """Extract formatted options from the payload."""
    options = {
        "enable_create_target": True,
        "enable_create_task": True,
        "enable_start_task": True,
    }
    user_opts = payload["options"]
    if "enable_create_target" in user_opts:
        options["enable_create_target"] = (
            True or user_opts["enable_create_target"] == "True"
        )
    if "enable_create_task" in user_opts:
        options["enable_create_task"] = (
            True or user_opts["enable_create_task"] == "True"
        )
    if "enable_start_task" in user_opts:
        options["enable_start_task"] = True or user_opts["enable_start_task"] == "True"
    return options


def get_target(
    target_name, scan_portlist_id=None, alive_test=AliveTest.TCP_SYN_SERVICE_PING
):
    """Return the target_id of a target. If not, it return None."""
    valid_target_id = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        # targets_xml = gmp_cnx.get_targets(filter="~"+target_name)
        targets_xml = gmp_cnx.get_targets(filter_string="~" + target_name)
        # print("get_target/targets_xml:", targets_xml)
        try:
            targets = ET.fromstring(targets_xml)
            # print("get_target/targets:", targets)
        except Exception as e:
            print(e)
            return None
        if not targets.attrib["status"] == "200":
            return None

        for target in targets.findall("target"):
            # print("get_target/target:", target, target_name, target.find("name").text)
            if scan_portlist_id is None and target_name in target.find("name").text:
                valid_target_id = target.get("id")
                if not is_uuid(valid_target_id):
                    valid_target_id = None
            elif (
                scan_portlist_id == target.find("port_list").get("id")
                and target_name in target.find("name").text
            ):
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
    # configs_xml = gmp.get_configs()
    configs_xml = gmp.get_scan_configs()
    try:
        configs = ET.fromstring(configs_xml)
    except Exception:
        return None

    for config in configs.findall("config"):
        if config.get("id") == scan_config_id:
            scan_config_name = config.find("name").text
            break

    if scan_config_name is None:
        return engine.scanner["options"]["default_scan_config_name"]["value"]
    else:
        return scan_config_name


def get_scan_config(name=None):
    """Return the scan_config_id from conf."""
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        # configs_xml = gmp_cnx.get_configs()
        configs_xml = gmp_cnx.get_scan_configs()
        try:
            configs = ET.fromstring(configs_xml)
        except Exception as e:
            print(e)
            return None

        scan_config_name = name
        if name is None:
            # Set the default value set in engine config
            scan_config_name = get_scan_config_name(gmp=gmp_cnx)

        for config in configs.findall("config"):
            tmp_config_name = config.find("name").text
            if scan_config_name == tmp_config_name:
                scan_config_id = config.get("id")
                if not is_uuid(scan_config_id, version=1) and not is_uuid(
                    scan_config_id
                ):
                    return None
                return scan_config_id
        return None
    connection.disconnect()


def create_target(
    target_name,
    target_hosts,
    port_list_id=None,
    port_list_name=None,
    ssh_credential_id=None,
    ssh_credential_port=None,
    smb_credential_id=None,
    esxi_credential_id=None,
    snmp_credential_id=None,
    alive_test=AliveTest.TCP_SYN_SERVICE_PING,
):
    """Create a target in OpenVAS and returns its target_id."""
    # Check alive_test param
    if alive_test not in OV_ALIVE_TESTS.keys():
        alive_test = AliveTest.TCP_SYN_SERVICE_PING
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        new_target_xml = gmp_cnx.create_target(
            "{} - {} - {}".format(target_name, port_list_name, alive_test),
            hosts=target_hosts,
            ssh_credential_id=ssh_credential_id,
            ssh_credential_port=ssh_credential_port,
            smb_credential_id=smb_credential_id,
            esxi_credential_id=esxi_credential_id,
            snmp_credential_id=snmp_credential_id,
            port_list_id=port_list_id,
            alive_test=alive_test,
        )
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
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        # tasks_xml = gmp_cnx.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg")
        tasks_xml = gmp_cnx.get_tasks(
            filter_string="apply_overrides=1 min_qod=0 rows=-1 levels=hmlg"
        )
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
            if (
                task.find("target").get("id") == target_id
                and task.find("config").get("id") == scan_config_id
            ):
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
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        scanners_xml = gmp_cnx.get_scanners()
        try:
            scanners = ET.fromstring(scanners_xml)
        except Exception:
            return None
        if not scanners.get("status") == "200":
            return None

        for scanner in scanners.findall("scanner"):
            if name is not None:
                if name == scanner.find("name").text:
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
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        new_task_xml = gmp_cnx.create_task(
            name=target_name
            + " - {}".format(get_scan_config_name(scan_config_id, gmp=gmp_cnx)),
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        try:
            new_task = ET.fromstring(new_task_xml)
        except Exception:
            connection.disconnect()
            return None
        if not new_task.get("status") == "201":
            connection.disconnect()
            return None

        task_id = new_task.get("id")
        if not is_uuid(task_id):
            connection.disconnect()
            return None
        connection.disconnect()
        return task_id


def start_task(task_id):
    """Start a task and returns a report_id."""
    report_id = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        start_scan_results_xml = gmp_cnx.start_task(task_id)
        try:
            start_scan_results = ET.fromstring(start_scan_results_xml)
        except Exception as e:
            print(e)
            connection.disconnect()
            return None
        if start_scan_results.get("status") != "202":
            connection.disconnect()
            return None

        report_id = start_scan_results.find("report_id").text
        if report_id == "0" or not is_uuid(report_id):
            report_id = None
    connection.disconnect()
    return report_id


def get_last_report(task_id):
    """Return the last report_id of a task_id."""
    last_report = None
    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
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


def get_multiple_report_status(info, gmp_cnx):
    """
    Get the status of a set of assets.

    Ex: {'task_id': xx, 'report_id': xx}.
    """
    assets_status = dict()
    # result_xml = gmp_cnx.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1")
    result_xml = gmp_cnx.get_tasks(filter_string="apply_overrides=1 min_qod=0 rows=-1")
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
    report = result.find(
        "task/[@id='{task_id}']/*/report[@id='{report_id}']".format(
            task_id=task_id, report_id=report_id
        )
    )
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
    """Return True is the string is probably an IP subnet."""
    try:
        IPNetwork(subnet)
    except (TypeError, ValueError, AddrFormatError):
        return False
    if "/" not in subnet:
        return False
    return True


def subnet_ips(subnet):
    """Return IP addresses from an IP subnet."""
    ips = []
    if is_ip_subnet(subnet):
        try:
            ips = [str(ip) for ip in IPNetwork(subnet)]
        except Exception:
            return ips
    return ips


def is_ip_range(subnet):
    """Return True is the string is probably an IP range."""
    ips = []
    try:
        ips = glob_to_iprange(subnet)
    except Exception:
        return []
    return ips


def range_ips(range):
    """Return IP addresses from an IP subnet."""
    ips = []
    if is_ip_range(range):
        ips = [str(ip) for ip in glob_to_iprange(range)]
    return ips


def split_port(asset_port):
    """Get protocol and port number from input."""
    port_number = "0"
    port_protocol = "tcp"
    try:
        if asset_port.split("/")[0].isnumeric():
            port_number = asset_port.split("/")[0]

        if asset_port.split("/")[1] in ["tcp", "udp"]:
            port_protocol = asset_port.split("/")[1]
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
    status()
    return jsonify(
        {
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
            },
        }
    )


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
            assets_map = engine.scans[scan_id]["assets_map"]

        scan_data = {
            "status": engine.scans[scan_id]["status"],
            "started_at": engine.scans[scan_id]["started_at"],
            "finished_at": engine.scans[scan_id]["finished_at"],
            "assets": engine.scans[scan_id]["assets"],
            "assets_map": assets_map,
        }
        if "info" in engine.scans[scan_id].keys():
            scan_data.update(
                {
                    "info": engine.scans[scan_id]["info"],
                }
            )
        scans.append({scan_id: scan_data})

    res.update({"nb_scans": len(engine.scans), "status": engine.status, "scans": scans})
    return jsonify(res)


def _status_scan(scan_id, gmp_cnx=None):
    scan_status = "SCANNING"
    if engine.scans[scan_id]["status"] in ["STARTED", "FINISHED"]:
        return scan_status

    if gmp_cnx is None:
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
        )
        with Gmp(connection) as gmp_cnx:
            gmp_cnx.authenticate(
                engine.scanner["options"]["gmp_username"]["value"],
                engine.scanner["options"]["gmp_password"]["value"],
            )
            scan_assets_status = get_multiple_report_status(
                engine.scans[scan_id]["info"], gmp_cnx
            )

        connection.disconnect()
    else:
        scan_assets_status = get_multiple_report_status(
            engine.scans[scan_id]["info"], gmp_cnx
        )

    if scan_assets_status is None:
        engine.scans[scan_id]["status"] = "UNKNOWN"
        return scan_status

    if scan_assets_status["status"] == "Done":
        if (
            "report_available" in engine.scans[scan_id].keys()
            and engine.scans[scan_id]["report_available"] is True
        ):
            scan_status = "FINISHED"
            engine.scans[scan_id]["finished_at"] = int(time.time() * 1000)
        else:
            scan_status = "SCANNING"

    engine.scans[scan_id]["status"] = scan_status
    return scan_assets_status


@app.route("/engines/openvas/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": engine.scans[scan_id]["reason"]})
        return jsonify(res)

    assets_status = _status_scan(scan_id)
    if engine.scans[scan_id]["status"] in ["SCANNING", "STARTED", "FINISHED"]:
        res.update({"status": engine.scans[scan_id]["status"]})
        if "info" in engine.scans[scan_id].keys():
            res.update(
                {
                    "info": engine.scans[scan_id]["info"],
                }
            )

    if assets_status is None:
        res.update({"status": "error", "reason": "Cannot find any report_status"})

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
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    task_id = engine.scans[scan_id]["info"]["task_id"]
    try:
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
        )
        with Gmp(connection) as gmp_cnx:
            gmp_cnx.authenticate(
                engine.scanner["options"]["gmp_username"]["value"],
                engine.scanner["options"]["gmp_password"]["value"],
            )
            gmp_cnx.stop_task(task_id)
            engine.scans[scan_id]["status"] = "STOPPED"
        connection.disconnect()
    except Exception:
        app.logger.debug("Unable to stop scan '{}'".format(scan_id))
        engine.scans[scan_id]["status"] = "ERROR"
    return engine.stop_scan(scan_id)


@app.route("/engines/openvas/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    # Remove the scan from the active scan list
    clean_scan(scan_id)
    return engine.getreport(scan_id)


def _loadconfig():
    """Load configuration file."""
    conf_file = APP_BASE_DIR + "/openvas.json"
    if not exists(conf_file):
        app.logger.error("Error: config file '{}' not found".format(conf_file))
        return False

    try:
        json_data = open(conf_file)
        engine.scanner = load(json_data)
        engine.scanner["status"] = "ERROR"
        engine.scanner["reason"] = "Starting loading configuration file"
    except Exception as ex:
        app.logger.error("Loadconfig: Error " + ex.__str__())
        return False

    try:
        response = ""
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
        )
        with Gmp(connection) as this.gmp:
            response = this.gmp.authenticate(
                engine.scanner["options"]["gmp_username"]["value"],
                engine.scanner["options"]["gmp_password"]["value"],
            )
    except Exception as ex:
        engine.scanner["status"] = "ERROR"
        engine.status = "ERROR"

        if ex.__str__() == "timed out":
            engine.scanner["reason"] = "connection to {}:{} timed-out".format(
                connection.hostname, connection.port
            )
        else:
            engine.scanner["reason"] = ex.__str__()

        app.logger.error("Loadconfig: Error " + ex.__str__())
        return False

    # Check login response
    if response.find('authenticate_response status="400"') > 0:
        engine.status = "ERROR"
        engine.scanner["status"] = "ERROR"
        engine.scanner["reason"] = "openvas login failed"
        app.logger.error("Loadconfig: Openvas login failed !")
        return False

    # Check port lists
    try:
        portlists = ET.fromstring(this.gmp.get_port_lists())
    except Exception:
        app.logger.error("Loadconfig: Unable to retrieve port lists.")
        return False

    for pl in portlists.findall("port_list"):
        pl_name = pl.find("name").text
        pl_uuid = pl.get("id")
        this.openvas_portlists.update({pl_name: pl_uuid})

    # Create custom port lists
    if "patrowl-all_tcp" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-all_tcp", port_range="T:1-65535"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-all_tcp": new_pl.get("id")})
        except Exception:
            app.logger.error("Loadconfig: Unable to create port list 'patrowl-all_tcp'")
            return False

    if "patrowl-quick_tcp" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-quick_tcp", port_range="T:21-80,T:443,U:53"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-quick_tcp": new_pl.get("id")})
        except Exception:
            app.logger.error(
                "Loadconfig: Unable to create port list 'patrowl-quick_tcp'"
            )
            return False

    if "patrowl-tcp_80" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_80", port_range="T:80"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_80": new_pl.get("id")})
        except Exception:
            app.logger.error("Loadconfig: Unable to create port list 'patrowl-tcp_80'")
            return False

    if "patrowl-tcp_443" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_443", port_range="T:443"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_443": new_pl.get("id")})
        except Exception:
            app.logger.error("Loadconfig: Unable to create port list 'patrowl-tcp_443'")
            return False

    if "patrowl-tcp_22" not in this.openvas_portlists.keys():
        try:
            new_pl_xml = this.gmp.create_port_list(
                name="patrowl-tcp_22", port_range="T:22"
            )
            new_pl = ET.fromstring(new_pl_xml)
            this.openvas_portlists.update({"patrowl-tcp_22": new_pl.get("id")})
        except Exception:
            app.logger.error("Loadconfig: Unable to create port list 'patrowl-tcp_22'")
            return False

    try:
        version_filename = APP_BASE_DIR + "/VERSION"
        if os.path.exists(version_filename):
            version_file = open(version_filename, "r")
            engine.version = version_file.read().rstrip("\n")
            version_file.close()
    except Exception as ex:
        app.logger.error("Loadconfig: Unable to read the VERSION file. " + ex.__str__())
        return False

    engine.scanner["status"] = "READY"
    engine.scanner["credentials"] = ()
    this.gmp.disconnect()

    app.logger.info("Loadconfig: Configuration file successfuly loaded. Let's go guy !")
    return True


@app.route("/engines/openvas/reloadconfig", methods=["GET"])
def reloadconfig():
    """Reload configuration file."""
    res = {"page": "reloadconfig"}
    _loadconfig()
    res.update({"config": engine.scanner})
    return jsonify(res)


@app.route("/engines/openvas/startscan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    res = {"page": "startscan"}

    # Check the scanner is ready to start a new scan
    if len(engine.scans) == APP_MAXSCANS:
        res.update(
            {
                "status": "error",
                "reason": "Scan refused: max concurrent active scans reached ({})".format(
                    APP_MAXSCANS
                ),
            }
        )
        return jsonify(res)

    status()
    if engine.scanner["status"] != "READY":
        res.update(
            {
                "status": "refused",
                "details": {
                    "reason": engine.scanner.get("reason", "scanner not ready"),
                    "status": engine.scanner["status"],
                },
            }
        )
        return jsonify(res)

    data = loads(request.data.decode("utf-8"))
    if "assets" not in data.keys() or "scan_id" not in data.keys():
        res.update(
            {
                "status": "refused",
                "details": {"reason": "arg error, something is missing ('assets' ?)"},
            }
        )
        app.logger.error(
            "StartScan: arg error, something is missing ('assets' or 'scan_id' ?)"
        )
        return jsonify(res)

    assets = []
    for asset in data["assets"]:
        # Value
        if "value" not in asset.keys() or not asset["value"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, something is missing ('asset.value')",
                }
            )
            return jsonify(res)

        # Supported datatypes
        if asset["datatype"] not in engine.scanner["allowed_asset_types"]:
            res.update(
                {
                    "status": "error",
                    "reason": "arg error, bad value for '{}' datatype (not supported)".format(
                        asset["value"]
                    ),
                }
            )
            return jsonify(res)

        if asset["datatype"] == "url":
            parsed_uri = urlparse(asset["value"])
            asset["value"] = parsed_uri.netloc

        assets.append(asset["value"])

    scan_id = str(data["scan_id"])

    scan = {
        "assets": assets,
        "threads": [],
        "options": data["options"],
        "scan_id": scan_id,
        "status": "STARTED",
        "reason": "",
        "lock": False,
        "started_at": int(time.time() * 1000),
        "finished_at": "",
        "findings": {},
    }

    engine.scans.update({scan_id: scan})
    thread = Thread(target=_scan_assets, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]["threads"].append(thread)

    res.update(
        {
            "status": "accepted",
            "details": {
                # "scan_id": scan["scan_id"]
                "scan_id": scan_id
            },
        }
    )

    return jsonify(res)


def _scan_assets(scan_id):
    """Scan assets from a scan."""
    scan = engine.scans[scan_id]

    scan_config_name = None
    if "profile" in engine.scans[scan_id]["options"].keys():
        scan_config_name = engine.scans[scan_id]["options"]["profile"]

    # print("scan_config_name:", scan_config_name)

    scan_config_id = get_scan_config(name=scan_config_name)
    # print("scan_config_id:", scan_config_id)
    scan_portlist_id = None
    if "OpenVAS Default" in this.openvas_portlists.keys():
        scan_portlist_id = this.openvas_portlists["OpenVAS Default"]
    scan_portlist_name = ""
    if "port_list" in scan["options"].keys():
        scan_portlist_name = scan["options"]["port_list"]
        if scan_portlist_name in this.openvas_portlists.keys():
            scan_portlist_id = this.openvas_portlists[scan_portlist_name]

    # print("scan_portlist_id:", scan_portlist_id)

    if scan_portlist_id is None:
        engine.scans[scan_id]["status"] = "ERROR"
        engine.scans[scan_id]["reason"] = "Port list unknown ('OpenVAS Default' ?)"
        return False

    options = get_options(scan)

    assets = engine.scans[scan_id]["assets"]
    assets_hash = hashlib.sha1(str("".join(assets)).encode("utf-8")).hexdigest()
    engine.scans[scan_id]["assets_hash"] = assets_hash

    try:
        target_id = get_target(assets_hash, scan_portlist_id)

        if target_id is None and options["enable_create_target"] is True:
            target_id = create_target(
                target_name=assets_hash,
                target_hosts=engine.scans[scan_id]["assets"],
                port_list_id=scan_portlist_id,
                port_list_name=scan_portlist_name,
            )  # Todo: add credentials if needed
        if target_id is None:
            engine.scans[scan_id]["status"] = "ERROR"
            engine.scans[scan_id]["reason"] = "Unable to create a target ({})".format(
                assets_hash
            )
            return False

        task_id = get_task_by_target_name(assets_hash, scan_config_id)
        if task_id is None and options["enable_create_task"] is True:
            task_id = create_task(assets_hash, target_id, scan_config_id=scan_config_id)
        if task_id is None:
            engine.scans[scan_id]["status"] = "ERROR"
            engine.scans[scan_id]["reason"] = "Unable to create a task ({})".format(
                assets_hash
            )
            return False

        if options["enable_start_task"] is True:
            report_id = start_task(task_id)
            if report_id is None:
                report_id = get_last_report(task_id)
        else:
            report_id = get_last_report(task_id)

        if report_id is None:
            engine.scans[scan_id]["status"] = "ERROR"
            engine.scans[scan_id]["reason"] = "Unable to get a report ({})".format(
                assets_hash
            )
            return False

        # Store the scan info
        engine.scans[scan_id]["info"] = {
            "task_id": task_id,
            "report_id": report_id,
            "status": "accepted",
        }
    except Exception as e:
        print(e)
        engine.scans[scan_id]["status"] = "ERROR"
        engine.scans[scan_id]["reason"] = "Error when trying to start the scan"
        return False

    # Scan is now running
    engine.scans[scan_id]["status"] = "SCANNING"

    # @todo: Wait max scan timeout
    max_scan_timeout = DEFAULT_SCAN_TIMEOUT
    try:
        if (
            "max_timeout" in engine.scans[scan_id]["options"].keys()
            and engine.scans[scan_id]["options"]["max_timeout"].isnumeric()
        ):
            max_scan_timeout = int(engine.scans[scan_id]["options"]["max_timeout"])
    except Exception:
        pass
    timeout = time.time() + max_scan_timeout

    while True:
        time.sleep(5)
        if time.time() > timeout:
            engine.scans[scan_id]["status"] = "ERROR"
            engine.scans[scan_id]["reason"] = (
                "Scan timeout exceeded: {} seconds.".format(timeout)
            )
            break

        scan_assets_status = _status_scan(scan_id)

        if engine.scans[scan_id]["status"].upper() in [
            "ERROR",
            "UNKNOWN",
            "STOPPED",
            "FINISHED",
        ]:
            break
        elif engine.scans[scan_id]["status"].upper() == "STARTED":
            continue
        elif engine.scans[scan_id]["status"].upper() == "SCANNING":
            if (
                scan_assets_status["status"] == "Done"
                and "report_available" not in engine.scans[scan_id].keys()
            ):
                try:
                    # Get the report from the OpenVAS instance
                    engine.scans[scan_id]["findings"] = get_report(scan_id)
                except Exception as e:
                    print(e)
                    engine.scans[scan_id]["status"] = "ERROR"
                    engine.scans[scan_id]["reason"] = (
                        "Unable to get findings from scan '{}'.".format(scan_id)
                    )
                    break

                # Parse the results
                try:
                    issues, summary = _parse_results(scan_id)
                except Exception as e:
                    print(e)
                    engine.scans[scan_id]["status"] = "ERROR"
                    engine.scans[scan_id]["reason"] = (
                        "Unable to parse findings from scan '{}'.".format(scan_id)
                    )
                    break

                scan = {
                    "scan_id": scan_id,
                    "assets": engine.scans[scan_id]["assets"],
                    "options": engine.scans[scan_id]["options"],
                    "status": engine.scans[scan_id]["status"],
                    "started_at": engine.scans[scan_id]["started_at"],
                    "finished_at": engine.scans[scan_id]["finished_at"],
                }

                # Store the findings in a file
                with open(
                    APP_BASE_DIR + "/results/openvas_" + scan_id + ".json", "w"
                ) as rf:
                    dump(
                        {"scan": scan, "summary": summary, "issues": issues},
                        rf,
                        default=_json_serial,
                    )

                engine.scans[scan_id]["status"] = "FINISHED"
                engine.scans[scan_id]["finished_at"] = int(time.time() * 1000)
                engine.scans[scan_id]["report_available"] = True

    return True


def get_report(scan_id):
    """Get report."""
    report_id = engine.scans[scan_id]["info"]["report_id"]
    # task_id = engine.scans[scan_id]["info"]["task_id"]
    issues = []

    assets_hash = engine.scans[scan_id]["assets_hash"]

    connection = TLSConnection(
        hostname=engine.scanner["options"]["gmp_host"]["value"],
        port=engine.scanner["options"]["gmp_port"]["value"],
        timeout=int(engine.scanner["options"].get("timeout", DEFAULT_TIMEOUT)),
    )
    with Gmp(connection) as gmp_cnx:
        gmp_cnx.authenticate(
            engine.scanner["options"]["gmp_username"]["value"],
            engine.scanner["options"]["gmp_password"]["value"],
        )
        if not isfile("results/openvas_report_{}_{}.xml".format(scan_id, assets_hash)):
            # # result = gmp_cnx.get_reports(filter="report_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id), details=1, override_details=1, note_details=1)
            # # result = gmp_cnx.get_reports(filter="task_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(task_id), details=1, override_details=1, note_details=1)
            # result = gmp_cnx.get_reports(filter="report_id={} task_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id, task_id), details=1, override_details=1, note_details=1)
            # result = gmp_cnx.get_reports(
            #     filter="report_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id),
            #     report_filter="task_id={}".format(task_id),
            #     details=1,
            #     override_details=1,
            #     note_details=1
            # )
            result = gmp_cnx.get_report(
                report_id=report_id,
                # filter="levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1",
                filter_string="levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1",
                details=1,
                ignore_pagination=1,
            )

            # result = gmp_cnx.get_results(filter="task_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(task_id), details=1, override_details=1, note_details=1)
            # result = gmp_cnx.get_results(filter="report_id={} task_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id, task_id), details=1, override_details=1, note_details=1)
            # result = gmp_cnx.get_results(
            #     # filter="report_id={} task_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id, task_id),
            #     filter="report_id={} levels=hmlg apply_overrides=0 rows=-1 min_qod=70 sort-reverse=severity notes=1 overrides=1".format(report_id),
            #     task_id=task_id,
            #     details=1,
            #     override_details=1,
            #     note_details=1
            # )
            result_file = open(
                "results/openvas_report_{}_{}.xml".format(scan_id, assets_hash), "w"
            )
            result_file.write(result)
            result_file.close()

        try:
            tree = ET.parse(
                "results/openvas_report_{}_{}.xml".format(scan_id, assets_hash)
            )
        except Exception as e:
            # No Element found in XML file
            app.logger.error(e)
            connection.disconnect()
            return {"status": "ERROR", "reason": "no issues found"}

        # Build the asset mapping
        assets_map = {}
        for asset in engine.scans[scan_id]["assets"]:
            asset_datatype = "fqdn"
            siblings = [asset]
            if is_domain(asset):
                asset_datatype = "domain"
            elif is_ip(asset):
                asset_datatype = "ip"
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
                        siblings.append(record.address)
                except Exception as e:
                    # What is that thing ?
                    app.logger.error(e)
                    pass

            assets_map.update(
                {
                    asset: {
                        "siblings": list(set(siblings)),
                        "datatype": asset_datatype,
                        "has_issues": False,
                    }
                }
            )

        engine.scans[scan_id]["assets_map"] = assets_map

        report = tree.getroot().find("report")  # Use with get_reports
        # report = tree.getroot()  # Use with get_results
        for result in report.findall(".//result"):
            try:
                if result.find("host") is None:
                    continue
                host_ip = result.find("host").text
                host_name = result.find("host").find("hostname")

                for a in assets_map.keys():
                    if host_ip in assets_map[a]["siblings"]:
                        issues.append(result)
                        engine.scans[scan_id]["assets_map"][a]["has_issues"] = True
                    elif (
                        host_name is not None
                        and host_name.text in assets_map[a]["siblings"]
                    ):
                        issues.append(result)
                        engine.scans[scan_id]["assets_map"][a]["has_issues"] = True

            except Exception as e:
                # probably unknown issue's host, skip it
                app.logger.error(
                    "Warning: failed to process issue: {}".format(
                        ET.tostring(result, encoding="utf8", method="xml")
                    )
                )
                app.logger.error(e)

    connection.disconnect()
    return issues


def _parse_results(scan_id):
    """Parse results to create findings."""
    issues = []
    summary = {}

    nb_vulns = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    timestamp = int(time.time() * 1000)

    # No issue
    if engine.scans[scan_id]["findings"] == {}:
        for asset in engine.scans[scan_id]["assets"]:
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "tcp"},
                    "title": "No results found.",
                    "solution": "n/a",
                    "metadata": {},
                    "type": "openvas_report",
                    "timestamp": timestamp,
                    "description": "No results found during the scan.",
                }
            )

    for asset in engine.scans[scan_id]["assets_map"].keys():
        if engine.scans[scan_id]["assets_map"][asset]["has_issues"] is False:
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "tcp"},
                    "title": "No results found.",
                    "solution": "n/a",
                    "metadata": {},
                    "type": "openvas_report",
                    "timestamp": timestamp,
                    "description": "No results found during the scan.",
                }
            )

    titles = []
    for result in engine.scans[scan_id]["findings"]:
        try:
            if result.find("nvt") is None:
                continue
            # Do not report an outdated or end-of-life scan engine
            if (
                result.find("nvt") is not None
                and "Report outdated" in result.find("nvt").find("name").text
            ):
                continue
            if (
                result.find("nvt") is not None
                and "Important Announcement" in result.find("nvt").find("name").text
            ):
                continue

            if result.find("severity") is not None:
                severity = float(result.find("severity").text)
            else:
                severity = "info"
            cve = []
            if result.find("nvt").find("cve") is not None:
                cve = [result.find("nvt").find("cve").text]
            threat = result.find("threat").text
            cvss_base = result.find("nvt").find("cvss_base").text
            name = result.find("nvt").find("name").text
            tags = result.find("nvt").find("tags").text
            refs = result.find("nvt").find("refs")
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
            for a in engine.scans[scan_id]["assets_map"].keys():
                if asset_name in engine.scans[scan_id]["assets_map"][a]["siblings"]:
                    if engine.scans[scan_id]["assets_map"][a]["datatype"] in [
                        "ip-range",
                        "ip-subnet",
                    ]:
                        asset_names.append(asset_name)
                    else:
                        asset_names.append(a)

                if (
                    asset_hostname is not None
                    and asset_hostname.text
                    in engine.scans[scan_id]["assets_map"][a]["siblings"]
                ):
                    asset_names.append(asset_hostname.text)
                    asset_names.append(asset_name)

            if len(asset_names) == 0:
                asset_names = [asset_name]

            # Remove duplicates
            asset_names = list(set(asset_names))

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

            # CVE
            if refs:
                for ref in refs.findall("ref"):
                    if ref.attrib["type"] == "cve":
                        cve.append(ref.attrib["id"])

            # form description
            description = "[{}] CVSS: {}\n\n".format(threat, severity)
            if len(cve) > 0:
                description += "Associated CVE: {}\n\n".format(", ".join(cve))

            if xmlDesc:
                description += xmlDesc + "\n\n"
            if tags:
                description += tags.replace("|", "\n") + "\n\n"

            # Solution
            solution_data = re.search("\|solution=(.+?)\|", tags)
            if solution_data and solution_data[0] != "|":
                solution = solution_data.group(1)

            #  metadata
            finding_metadata = {"risk": {"cvss_base_score": cvss_base}, "vuln_refs": {}}
            # CVE
            if len(cve) > 0:
                finding_metadata.update({"vuln_refs": {"CVE": cve}})

            # CPE
            try:
                if name == "CPE Inventory":
                    finding_metadata.update(
                        {
                            "vuln_refs": {
                                "CPE": [c.split("|")[1] for c in xmlDesc.split("\n")]
                            }
                        }
                    )
            except Exception:
                pass

            try:
                if name == "CPE Inventory":
                    finding_metadata.update(
                        {
                            "vuln_refs": {
                                "CPE": [c.split("|")[1] for c in xmlDesc.split("\n\n")]
                            }
                        }
                    )
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
            issues.append(
                {
                    "issue_id": len(issues) + 1,
                    "severity": criticity,
                    "confidence": "certain",
                    "target": {"addr": asset_names, "protocol": asset_port_protocol},
                    "title": title,
                    "solution": solution,
                    "metadata": finding_metadata,
                    "type": "openvas_report",
                    "timestamp": timestamp,
                    "description": description,
                }
            )
            # print("new_issue", issues[-1])

            xmlDesc = ""

        except Exception as e:
            # probably unknown issue's host, skip it
            app.logger.error(
                "Warning: failed to process issue: {}".format(
                    ET.tostring(result, encoding="utf8", method="xml")
                )
            )
            app.logger.error(e)
            if hasattr(e, "message"):
                app.logger.error(e.message)

    summary = {
        "nb_issues": len(issues),
        "nb_info": nb_vulns["info"],
        "nb_low": nb_vulns["low"],
        "nb_medium": nb_vulns["medium"],
        "nb_high": nb_vulns["high"],
        "nb_critical": nb_vulns["critical"],
        "engine_name": "openvas",
        "engine_version": engine.scanner["version"],
    }

    return issues, summary


@app.route("/engines/openvas/getfindings/<scan_id>", methods=["GET"])
def getfindings(scan_id):
    """Get findings from a finished scan."""
    res = {"page": "getfindings", "scan_id": scan_id}

    # check if the scan_id exists
    if scan_id not in engine.scans.keys():
        res.update(
            {"status": "error", "reason": "scan_id '{}' not found".format(scan_id)}
        )
        return jsonify(res)

    # check if the scan is finished
    # status()
    _status_scan(scan_id)
    if engine.scans[scan_id]["status"] != "FINISHED":
        res.update(
            {
                "status": "error",
                "reason": "scan_id '{}' not finished (status={})".format(
                    scan_id, engine.scans[scan_id]["status"]
                ),
            }
        )
        return jsonify(res)

    try:
        with open(APP_BASE_DIR + "/results/openvas_" + scan_id + ".json", "r") as rf:
            json_report = load(rf)
    except Exception:
        res.update(
            {
                "status": "error",
                "reason": "Unable to get report and findings from scan '{}'".format(
                    scan_id
                ),
            }
        )
        return jsonify(res)

    res.update(
        {
            "scan": json_report["scan"],
            "summary": json_report["summary"],
            "issues": json_report["issues"],
            "status": "success",
        }
    )
    return jsonify(res)


@app.before_first_request
def main():
    """First function called."""
    if not exists(APP_BASE_DIR + "/results"):
        makedirs(APP_BASE_DIR + "/results")
    res = _loadconfig()
    if res is False:
        app.logger.error(
            "Unable to initialize the engine with provided configuration file."
        )


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
