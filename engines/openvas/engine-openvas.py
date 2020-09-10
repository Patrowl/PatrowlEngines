#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVAS PatrOwl engine application."""

from os import makedirs
from os.path import dirname, exists, isfile, realpath
from sys import modules
from json import dump, load, loads
# from re import search as re_search
from netaddr import IPNetwork, IPAddress, glob_to_iprange
from netaddr.core import AddrFormatError
from threading import Thread
from time import time, sleep
from urllib.parse import urlparse
from uuid import UUID
import xml.etree.ElementTree as ET

# Third party library imports
from flask import Flask, request, jsonify
from dns.resolver import query
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv7.types import AliveTest

# Own library
from PatrowlEnginesUtils.PatrowlEngine import _json_serial
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Debug
# from pdb import set_trace as st

app = Flask(__name__)
APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = 5
APP_ENGINE_NAME = "openvas"
APP_BASE_DIR = dirname(realpath(__file__))
DEFAULT_OV_PROFILE = "Full and fast"
DEFAULT_OV_PORTLIST = "patrowl-all_tcp"

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
    """
    This functionuuid_string returns True is the uuid_string is a valid UUID.
    """
    try:
        uid = UUID(uuid_string, version=version)
        return uid.hex == uuid_string.replace("-", "")
    except ValueError:
        return False


def get_options(payload):
    """
    Extracts formatted options from the payload.
    """
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
    """
    This function returns the target_id of a target. If not, it returns None.
    """
    targets_xml = this.gmp.get_targets()
    try:
        targets = ET.fromstring(targets_xml)
    except Exception:
        return None
    if not targets.attrib["status"] == "200":
        return None

    # Debug
    # for target in targets.findall("target"):
    #     print(target.find("hosts"))

    for target in targets.findall("target"):
        if scan_portlist_id is None and target_name == target.find("hosts").text:
            target_id = target.get("id")
            if not is_uuid(target_id):
                return None
            return target_id
        elif scan_portlist_id == target.find("port_list").get('id') and target_name == target.find("hosts").text:
            target_id = target.get("id")
            if not is_uuid(target_id):
                return None
            return target_id

    return None


def get_credentials(name=None):
    """
    This function returns the credentials_id from conf.
    """
    result_xml = this.gmp.get_credentials()
    try:
        result = ET.fromstring(result_xml)
    except Exception:
        return None
    if not result.attrib["status"] == "200":
        return None

    creds_name = name
    if name is None:
        # Set the default value set in engine config
        creds_name = engine.scanner["options"]["default_credential_name"]["value"]

    for credential in result.findall("credential"):
        if credential.find("name").text == creds_name:
            credentials_id = credential.attrib["id"]
            if not is_uuid(credentials_id):
                return None
            return credentials_id
    return None


def get_scan_config_name(scan_config_id=None):
    scan_config_name = None

    configs_xml = this.gmp.get_configs()
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
    """
    This function returns the scan_config_id from conf.
    """
    configs_xml = this.gmp.get_configs()
    try:
        configs = ET.fromstring(configs_xml)
    except Exception:
        return None

    scan_config_name = name
    if name is None:
        # Set the default value set in engine config
        scan_config_name = get_scan_config_name()

    for config in configs.findall("config"):
        tmp_config_name = config.find("name").text
        if scan_config_name == tmp_config_name:
            scan_config_id = config.get("id")
            if not is_uuid(scan_config_id, version=1) and not is_uuid(scan_config_id):
                return None
            return scan_config_id
    return None


def create_target(
    target_name,
    port_list_id=None,
    port_list_name=None,
    ssh_credential_id=None, ssh_credential_port=None,
    smb_credential_id=None,
    esxi_credential_id=None,
    snmp_credential_id=None,
    # alive_test="TCP_SYN_SERVICE_PING"):
    alive_test=AliveTest.TCP_SYN_SERVICE_PING):
    """
    This function creates a target in OpenVAS and returns its target_id.
    """
    # app.logger.debug(
    #     "create_target(): {}, {}, {}, {}",
    #     target_name, port_list_id, port_list_name, alive_test)

    # Check alive_test param
    if alive_test not in OV_ALIVE_TESTS.keys():
        # alive_test = OV_ALIVE_TESTS["DEFAULT"]
        # alive_test = "TCP_SYN_SERVICE_PING"
        alive_test = AliveTest.TCP_SYN_SERVICE_PING

    new_target_xml = this.gmp.create_target(
        "{} - {} - {}".format(target_name, port_list_name, alive_test),
        hosts=[target_name],
        ssh_credential_id=ssh_credential_id,
        ssh_credential_port=ssh_credential_port,
        smb_credential_id=smb_credential_id,
        esxi_credential_id=esxi_credential_id,
        snmp_credential_id=snmp_credential_id,
        port_list_id=port_list_id,
        # alive_test=OV_ALIVE_TESTS[alive_test]
        alive_test=alive_test
        )
    try:
        new_target = ET.fromstring(new_target_xml)
    except Exception as e:
        app.logger.error(e)
        return None
    if not new_target.get("status") == "201":
        return None
    target_id = new_target.get("id")
    if not is_uuid(target_id):
        return None
    return target_id


def get_task_by_target_name(target_name, scan_config_id=None):
    """
    This function returns the task_id.
    """
    # tasks_xml = this.gmp.get_tasks()
    # tasks_xml = this.gmp.get_tasks(apply_overrides=1)
    tasks_xml = this.gmp.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1")
    target_id = get_target(target_name)
    if target_id is None:
        return None
    try:
        tasks = ET.fromstring(tasks_xml)
    except Exception:
        return None
    if not tasks.get("status") == "200":
        return None

    # scan_config_id = get_scan_config(scan_config_name)

    for task in tasks.findall("task"):
        if task.find('target').get("id") == target_id and task.find('config').get('id') == scan_config_id:
            task_id = task.get("id")
            if not is_uuid(task_id):
                return None
            return task_id

    return None


def get_scanners(name=None):
    """
    This function returns the list of scanners' ID.
    """
    scanners_xml = this.gmp.get_scanners()
    try:
        scanners = ET.fromstring(scanners_xml)
    except Exception:
        return None
    if not scanners.get("status") == "200":
        return None

    scanners_list = []

    for scanner in scanners.findall("scanner"):
        if name is not None:
            if name == scanner.find('name').text:
                return [scanner.get("id")]
        else:
            scanners_list.append(scanner.get("id"))
    return scanners_list


def create_task(target_name, target_id, scan_config_id=None, scanner_id=None):
    """
    This function creates a task_id in OpenVAS and returns its task_id.
    """
    if scan_config_id is None:
        scan_config_id = get_scan_config()  # Set the default value
    if scanner_id is None:
        scanner_id = get_scanners()[1]  # Set the default value

    # print("create_task:", scan_config_id, get_scan_config_name(scan_config_id))

    new_task_xml = this.gmp.create_task(
        name=target_name + " - {}".format(get_scan_config_name(scan_config_id)),
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
    return task_id


def start_task(task_id):
    """
    This function starts a task and returns a report_id.
    """
    start_scan_results_xml = this.gmp.start_task(task_id)

    try:
        start_scan_results = ET.fromstring(start_scan_results_xml)
    except Exception:
        return None
    if not start_scan_results.get("status") == "202":
        return None
    report_id = start_scan_results.find("report_id").text
    if report_id == "0" or not is_uuid(report_id):
        return None
    return report_id


def get_last_report(task_id):
    """
    This function returns the last report_id of a task_id
    """
    task_xml = this.gmp.get_task(task_id)
    try:
        task = ET.fromstring(task_xml)
    except Exception:
        return None
    if not task.get("status") == "200":
        return None

    try:
        last_report = task.find("task").find("last_report").find("report")
    except Exception:
        return None
    if not is_uuid(last_report.get("id")):
        return None
    return last_report.get("id")


def get_report_status(report_id):
    """
    This function get the status of a report_id.
    """
    report_status_xml = this.gmp.get_report(report_id, filter="apply_overrides=1 min_qod=0 rows=-1")
    try:
        report_status = ET.fromstring(report_status_xml)
    except Exception:
        return None
    if not report_status.get("status") == "200":
        return None

    return report_status.find("report").find("report").find("scan_run_status").text


def get_multiple_report_status(assets):
    """
    This function get the status of a set of assets {'task_id': xx, 'report_id': xx}
    """
    assets_status = dict()
    # result_xml = this.gmp.get_tasks()
    result_xml = this.gmp.get_tasks(filter="apply_overrides=1 min_qod=0 rows=-1")
    # result_xml = this.gmp.get_tasks(apply_overrides=1)
    try:
        result = ET.fromstring(result_xml)
    except Exception:
        return None
    if not result.attrib["status"] == "200":
        return None
    for asset in assets:
        task_id = assets[asset]["task_id"]
        report_id = assets[asset]["report_id"]
        report = result.find("task/[@id='{task_id}']/*/report[@id='{report_id}']".format(
            task_id=task_id, report_id=report_id))
        if report is None:
            # print("Can't find task_id={task_id}, report_id={report_id}".format(
            #     task_id=task_id, report_id=report_id))
            assets_status.update({asset: {"status": "Failure"}})
        else:
            scan_end = report.find("scan_end").text
            if scan_end is None:
                assets_status.update({asset: {"status": "Running"}})
            else:
                assets_status.update({asset: {"status": "Done"}})
    return assets_status


def is_ip(string):
    """Return True is the string is probably an IP."""
    try:
        IPAddress(string)
    except Exception:
        return False
    return True
    # return re_search("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", string) is not None


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
            "reason": engine.scanner.get("reason",""),
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
        engine.getstatus_scan(scan_id)
        scans.append({scan_id: {
            "status": engine.scans[scan_id]['status'],
            "started_at": engine.scans[scan_id]['started_at'],
            "assets": engine.scans[scan_id]['assets']
        }})

    res.update({
        "nb_scans": len(engine.scans),
        "status": engine.status,
        "scans": scans})
    return jsonify(res)

    # return engine.getstatus()


@app.route("/engines/openvas/status/<scan_id>")
def status_scan(scan_id):
    """Get status on scan identified by id."""
    res = {"page": "status", "status": "UNKNOWN"}
    if scan_id not in engine.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    if engine.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res)

    report_status = "Done"

    assets = engine.scans[scan_id]["assets"]
    assets_status = get_multiple_report_status(assets)
    if assets_status is None:
        res.update({"status": "error", "reason": "Cannot find any report_status"})
        return jsonify(res)

    for asset in assets:
        if assets_status[asset]["status"] != "Done":
            report_status = assets_status[asset]["status"]

    engine.scans[scan_id]["scan_status"] = report_status

    if engine.scans[scan_id]["scan_status"] == "Done":
        res.update({"status": "FINISHED"})
        engine.scans[scan_id]["status"] = "FINISHED"
        # Get the last version of the report
        try:
            _scan_urls(scan_id)
        except Exception as e:
            app.logger.error(e)
            res.update({
                "status": "error",
                "reason": "scan_urls did not worked ! ({})".format(e)})
            return jsonify(res)
    else:
        res.update({"status": "SCANNING"})
        for asset in assets:
            res.update({asset: assets_status[asset]["status"]})
        engine.scans[scan_id]["status"] = "SCANNING"

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

    for asset in engine.scans[scan_id]['assets'].keys():
        task_id = engine.scans[scan_id]['assets'][asset]['task_id']
        try:
            this.gmp.stop_task(task_id)
        except Exception:
            app.logger.debug("Unable to stop scan '{}'".format(scan_id))
            pass
    return engine.stop_scan(scan_id)


@app.route("/engines/openvas/getreport/<scan_id>")
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


def _loadconfig():
    conf_file = APP_BASE_DIR+"/openvas.json"
    if not exists(conf_file):
        app.logger.error("Error: config file '{}' not found".format(conf_file))
        return False

    json_data = open(conf_file)
    engine.scanner = load(json_data)

    try:
        response = ""
        connection = TLSConnection(
            hostname=engine.scanner["options"]["gmp_host"]["value"],
            port=engine.scanner["options"]["gmp_port"]["value"],
            timeout=engine.scanner["options"].get("timeout", 5)
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
        "lock":         False,
        "started_at":   int(time() * 1000),
        "findings":     {}
    }

    scan_config_name = None
    if 'profile' in data["options"].keys():
        scan_config_name = data["options"]["profile"]
    scan_config_id = get_scan_config(name=scan_config_name)

    scan_portlist_id = None
    scan_portlist_name = ""
    if 'port_list' in data["options"].keys():
        scan_portlist_name = data["options"]["port_list"]
        if scan_portlist_name in this.openvas_portlists.keys():
            scan_portlist_id = this.openvas_portlists[scan_portlist_name]
        else:
            scan_portlist_id = this.openvas_portlists["OpenVAS Default"]
    else:
        scan_portlist_id = this.openvas_portlists["OpenVAS Default"]

    options = get_options(data)

    assets_failure = list()
    scan["assets"] = dict()

    for asset in assets:
        # print("== {} ==".format(asset))
        target_id = get_target(asset, scan_portlist_id)
        if target_id is None and options["enable_create_target"]:
            # print("Create target {}".format(asset))
            # target_id = create_target(asset)  # Todo: add credentials if needed
            target_id = create_target(
                asset,
                port_list_id=scan_portlist_id,
                port_list_name=scan_portlist_name)  # Todo: add credentials if needed
        if target_id is None:
            # if options["enable_create_target"]:
            #     print("Fail to create target {}".format(asset))
            # else:
            #     print("Target creation disabled")
            assets_failure.append(asset)
        else:
            task_id = get_task_by_target_name(asset, scan_config_id)
            if task_id is None and options["enable_create_task"]:
                # print("Create task {}".format(asset))
                task_id = create_task(asset, target_id, scan_config_id=scan_config_id)
            if task_id is None:
                # if options["enable_create_task"]:
                #     print("Fail to create task {}".format(asset))
                # else:
                #     print("Task creation disabled")
                assets_failure.append(asset)
            else:
                if options["enable_start_task"]:
                    report_id = start_task(task_id)
                    if report_id is None:
                        # print("Get last report of {}".format(task_id))
                        report_id = get_last_report(task_id)
                else:
                    # print("Start task disabled, get last report of {}".format(task_id))
                    report_id = get_last_report(task_id)
                if report_id is None:
                    # if options["enable_start_task"]:
                    #     print("Fail to start task {}".format(task_id))
                    # else:
                    #     print("Task start disabled")
                    assets_failure.append(asset)
                else:
                    # print("OK for report_id {}".format(report_id))
                    scan["assets"].update({
                        asset: {
                            "task_id": task_id,
                            "report_id": report_id,
                            "status": "accepted"
                        }
                    })

    # if scan["assets"] == dict():
    #     res.update({
    #         "status": "refused",
    #         "details": {
    #             "reason": "scan '{}' is probably already launched".format(data["scan_id"]),
    #         }
    #     })
    #     return jsonify(res)

    engine.scans.update({scan_id: scan})
    thread = Thread(target=_scan_urls, args=(scan_id,))
    thread.start()
    engine.scans[scan_id]["threads"].append(thread)

    res.update({
        "status": "accepted",
        "details": {
            "scan_id": scan["scan_id"]
        }
    })

    return jsonify(res)


def _scan_urls(scan_id):
    # Is it locked ?
    if engine.scans[scan_id]["lock"]:
        # print("locked")
        return True

    # Does the scan is terminated ?
    if "scan_status" in engine.scans[scan_id].keys():
        scan_status = engine.scans[scan_id]["scan_status"]
    else:
        return True
    if scan_status != "Done":
        return True

    engine.scans[scan_id]["lock"] = True
    # print("lock on")

    assets = []
    for asset in engine.scans[scan_id]["assets"]:
        assets.append(asset)

    for asset in assets:
        if asset not in engine.scans[scan_id]["findings"]:
            engine.scans[scan_id]["findings"][asset] = {}
        try:
            engine.scans[scan_id]["findings"][asset]["issues"] = get_report(asset, scan_id)
        except Exception:
            # print("_scan_urls: API Connexion error (quota?)")
            # print(e)
            engine.scans[scan_id]["lock"] = False
            return False

    # print("lock off")
    engine.scans[scan_id]["lock"] = False
    return True


def get_report(asset, scan_id):
    """Get report."""
    report_id = engine.scans[scan_id]["assets"][asset]["report_id"]
    issues = []

    if not isfile("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset.replace('/', 'net'))):
        result = this.gmp.get_report(report_id, filter="apply_overrides=1 min_qod=0 rows=-1")
        result_file = open("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset.replace('/', 'net')), "w")
        result_file.write(result)
        result_file.close()

    try:
        tree = ET.parse("results/openvas_report_{scan_id}_{asset}.xml".format(scan_id=scan_id, asset=asset.replace('/', 'net')))
    except Exception as e:
        # No Element found in XML file
        app.logger.error(e)
        return {"status": "ERROR", "reason": "no issues found"}

    if is_ip(asset):
        # app.logger.debug("is_ip:", asset)
        resolved_asset_ips = [asset]
    elif is_ip_subnet(asset):
        # app.logger.debug("is_ip_subnet:", asset)
        resolved_asset_ips = subnet_ips(asset)
    elif is_ip_range(asset):
        # app.logger.debug("is_ip_subnet:", asset)
        resolved_asset_ips = range_ips(asset)
    else:
        # app.logger.debug("else:", asset)
        # Let's suppose it's a fqdn then...
        try:
            resolved_asset_ips = []
            records = query(asset).response.answer[0].items
            for record in records:
                resolved_asset_ips.append(record.address)
        except Exception as e:
            # What is that thing ?
            return issues

    # app.logger.debug(resolved_asset_ips)

    report = tree.getroot().find("report")
    for result in report.findall('.//result'):
        try:
            host_ip = result.find("host").text
            if host_ip in resolved_asset_ips:
                issues.append(result)
        except Exception as e:
            # probably unknown issue's host, skip it
            app.logger.error("Warning: failed to process issue: {}".format(ET.tostring(result, encoding='utf8', method='xml')))
            app.logger.error(e)

    return issues


def _parse_results(scan_id):
    while engine.scans[scan_id]["lock"]:
        # print("report is not terminated yet, going to sleep")
        sleep(10)

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

    for asset in engine.scans[scan_id]["findings"]:
        # Do not try to extract issues if not exists
        if "issues" not in engine.scans[scan_id]["findings"][asset].keys():
            continue

        if len(engine.scans[scan_id]["findings"][asset]["issues"]) == 0:
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
        else:
            # report_id = engine.scans[scan_id]["assets"][asset]["report_id"]
            for result in engine.scans[scan_id]["findings"][asset]["issues"]:
                try:
                    if "Report outdated" in result.find("nvt").find("name").text:
                        # Do not report an outdated or end-of-life scan engine
                        continue
                    severity = float(result.find("severity").text)
                    cve = result.find("nvt").find("cve").text
                    threat = result.find("threat").text
                    cvss_base = result.find("nvt").find("cvss_base").text
                    name = result.find("nvt").find("name").text
                    tags = result.find("nvt").find("tags").text
                    xmlDesc = result.find("description").text
                    asset_name = result.find("host").text
                    asset_port = result.find("port").text
                    asset_port_number, asset_port_protocol = split_port(asset_port)

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
                            description += tags + "\n\n"

                        #  metadata
                        finding_metadata = {
                            "risk": {"cvss_base_score": cvss_base},
                            "vuln_refs": {
                                "CPE": []
                            }
                        }
                        # CVE
                        if cve != "NOCVE":
                            finding_metadata.update({
                                "vuln_refs": {"CVE": [cve]}
                            })

                        # CPE
                        if name == "CPE Inventory":
                            finding_metadata.update({
                                "vuln_refs": {"CPE": [c.split("|")[1] for c in xmlDesc.split("\n")]}
                            })

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
                                "addr": [asset_name],
                                "protocol": asset_port_protocol
                            },
                            "title": "{port} - {name}".format(port=asset_port, name=name),
                            "solution": "n/a",
                            "metadata": finding_metadata,
                            "type": "openvas_report",
                            "timestamp": timestamp,
                            "description": description,
                        })

                        xmlDesc = ""
                except Exception as e:
                    # probably unknown issue's host, skip it
                    app.logger.error("Warning: failed to process issue: {}".format(ET.tostring(result, encoding='utf8', method='xml')))
                    app.logger.error(e.message)
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


if __name__ == "__main__":
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
