#!/usr/bin/python
# -*- coding: utf-8 -*-

### Generic imports
import os, signal, sys, threading
from flask import Flask, request, redirect, url_for, jsonify
from utils.PatrowlEngine import PatrowlEngine, PatrowlEngineFinding, PatrowlEngineScan
from utils.PatrowlEngineExceptions import PatrowlEngineExceptions

# Custom imports
from datetime import timedelta, date, datetime
import re, hashlib, time, subprocess, json, shutil, git, svn.remote

APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5013
APP_MAXSCANS = 25
APP_ENGINE_NAME = "owl_code"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)

@app.errorhandler(404)
def page_not_found(e): return engine.page_not_found()

@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response

@app.route('/')
def default(): return engine.default()

@app.route('/engines/owl_code/')
def index(): return engine.index()

@app.route('/engines/owl_code/test')
def test(): return engine.test()

@app.route('/engines/owl_code/reloadconfig')
def reloadconfig(): return engine.reloadconfig()

@app.route('/engines/owl_code/info')
def info(): return engine.info()

@app.route('/engines/owl_code/clean')
def clean(): return engine.clean()

@app.route('/engines/owl_code/clean/<scan_id>')
def clean_scan(scan_id): return engine.clean_scan(scan_id)

@app.route('/engines/owl_code/status')
def status(): return engine.getstatus()

@app.route('/engines/owl_code/status/<scan_id>')
def status_scan(scan_id): return engine.getstatus_scan(scan_id)

@app.route('/engines/owl_code/stopscans')
def stop(): return engine.stop()

@app.route('/engines/owl_code/stop/<scan_id>')
def stop_scan(scan_id): return engine.stop_scan(scan_id)

@app.route('/engines/owl_code/getfindings/<scan_id>')
def getfindings(scan_id): return engine.getfindings(scan_id)

@app.route('/engines/owl_code/startscan', methods=['POST'])
def start_scan():

    # Check params and prepare the PatrowlEngineScan
    res = engine.init_scan(request.data)
    if "status" in res.keys() and res["status"] != "INIT":
        return jsonify(res)

    scan_id = res["details"]["scan_id"]

    if "scan_js" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["scan_js"] == True:
        for asset in engine.scans[scan_id]["assets"]:
            th = threading.Thread(target=_scanjs_thread, args=(scan_id, asset["value"],))
            th.start()
            engine.scans[scan_id]['threads'].append(th)

    if "scan_owaspdc" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["scan_owaspdc"] == True:
        for asset in engine.scans[scan_id]["assets"]:
            th = threading.Thread(target=_scanowaspdc_thread, args=(scan_id, asset["value"],))
            th.start()
            engine.scans[scan_id]['threads'].append(th)

    engine.scans[scan_id]['status'] = "SCANNING"

    # Finish
    res.update({"status": "accepted"})
    return jsonify(res)


def _get_code_from_git_http(asset, wd):
    # Check credentials
    git_username = ""
    git_password = ""
    #github_access_token = ""

    if "git_username" in engine.options.keys() and engine.options["git_username"]:
        git_username = engine.options["git_username"]
    if "git_username" in engine.options.keys() and engine.options["git_username"]:
        git_password = engine.options["git_username"]
        # if "git_accesstoken" in engine.options.keys() and engine.options["git_accesstoken"]:
        #     git_accesstoken = engine.options["git_accesstoken"]

    repo = git.Repo.init(wd+"/src")
    with repo.git.custom_environment(GIT_USERNAME=git_username, GIT_PASSWORD=git_password):
        origin = repo.create_remote('origin', asset)
        origin.fetch()
        origin.pull(origin.refs[0].remote_head)

    # git.Repo.clone_from(asset, wd+"/src", depth=1)

    return True

def _get_code_from_svn_http(scan_id, asset, wd):
    svn_username = ""
    svn_password = ""

    # check user/pass passed using the scan policy
    if "credentials" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["credentials"]:
        if "svn_username" in engine.scans[scan_id]["options"]["credentials"].keys():
            svn_username = engine.scans[scan_id]["options"]["credentials"]["svn_username"]
        if "svn_password" in engine.scans[scan_id]["options"]["credentials"].keys():
            svn_password = engine.scans[scan_id]["options"]["credentials"]["svn_password"]
    else:
        # default engine credentials
        if "svn_username" in engine.options.keys(): svn_username = engine.options["svn_username"]
        if "svn_password" in engine.options.keys(): svn_username = engine.options["svn_password"]

    #print "svn_username:", svn_username, " svn_password:", svn_password

    r = svn.remote.RemoteClient(asset, username=svn_username, password=svn_password)
    r.checkout(wd)

    return True


def _check_location(scan_id, asset, wd):
    if asset[0] == "/" or asset.startswith("file:///"):
        shutil.rmtree(wd)
        shutil.copytree(asset, wd)
        return True
    elif asset.startswith("https://github.com/"):
        # GITHUB+HTTP(s)
        return _get_code_from_git_http(asset, wd)
    elif asset.startswith("https://") or asset.startswith("http://"):

        # GIT+HTTP(s)
        if "repo_type" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["repo_type"] == "git":
            return _get_code_from_git_http(asset, wd)

        # SVN+HTTP(s)
        if "repo_type" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["repo_type"] == "svn":
            return _get_code_from_svn_http(scan_id, asset, wd)
    # elif asset.startwith("svn+ssh://"):
    #     return "svn+ssh"
    # elif asset.startwith("ssh://git@github.com"):
    #     return "github+ssh"


    return False


def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def _scanjs_thread(scan_id, asset_kw):
    issue_id = 0
    findings = []
    asset_values = [a["value"] for a in engine.scans[scan_id]["assets"]]

    # Create the scan's workdirs
    scan_wd = "{}/workdirs/scan_{}_{}".format(APP_BASE_DIR, scan_id, str(time.time()))
    if not os.path.exists(APP_BASE_DIR+"/workdirs"):
        os.makedirs(APP_BASE_DIR+"/workdirs")
    if not os.path.exists(scan_wd):
        os.makedirs(scan_wd)

    for asset_value in asset_values:
        checked_files = []
        # create the asset scan workdir
        scan_wd_asset = "{}/{}".format(scan_wd, hashlib.sha1(asset_value).hexdigest()[:6])
        os.makedirs(scan_wd_asset)

        # Check location and copy files to the workdir
        if not _check_location(scan_id, asset_value, scan_wd_asset):
            # Generate an error if it was not possible to get the source code
            summary_asset_finding = PatrowlEngineFinding(
                issue_id=issue_id, type="code_ext_js_summary",
                title="Retire.js scan not performed for '{}' (Error)".format(asset_value),
                description="Scan error with source code available at this location: '{}'. Unknwon error.".format(asset_value),
                solution="n/a.",
                severity="info", confidence="firm",
                raw={},
                target_addrs=[asset_value],
                meta_tags=["js", "library", "retire.js"])
            issue_id+=1
            findings.append(summary_asset_finding)
            continue

        time.sleep(2)

        # Start the scan
        report_filename = "{}/oc_{}.json".format(scan_wd_asset, scan_id)
        cmd = 'retire -j --path="{}" --outputformat json --outputpath="{}" -v'.format(
            scan_wd_asset, report_filename)
        #p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        p = subprocess.Popen(cmd, shell=True, stdout=open("/dev/null", "w"), stderr=None)

        # Wait a little to ensure the report file is completely writen
        p.wait()
        time.sleep(2)
        if not os.path.exists(report_filename):
            print("report file '{}' not found.".format(report_filename))
            engine.scans[scan_id]["status"] = "ERROR"
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            # if psutil.pid_exists(p):
            #     psutil.Process(p).terminate()
            return

        scan_results = json.load(open(report_filename))

        for item in scan_results:
            checked_files.append(item["file"])
            if len(item["results"]) == 0: continue

            for result in item["results"]:
                if "vulnerabilities" not in result.keys(): continue
                for vuln in result["vulnerabilities"]:
                    vuln_summary = "n/a"
                    if "summary" in vuln["identifiers"].keys():
                        vuln_summary = vuln["identifiers"]["summary"]
                    # Title
                    item_title = "'{}-{}' is vulnerable: '{}'".format(
                        result["component"], result["version"],
                        vuln_summary)

                    # Description
                    item_description = "An external JavaScript library has been found to be vulnerable:\n\nFilename: {}\nComponent: {}\nVersion: {}\nTitle: {}".format(
                        item["file"], result["component"], result["version"],
                        vuln_summary
                    )

                    # Check CVE
                    item_vuln_refs = {}
                    if "CVE" in vuln["identifiers"].keys():
                        item_vuln_refs.update({"CVE": vuln["identifiers"]["CVE"]})

                    new_finding = PatrowlEngineFinding(
                        issue_id=issue_id, type="code_js_missing_update",
                        title=item_title,
                        description=item_description,
                        solution="Check the exploitability of the vulnerability in the application context. If the vulnerability is verified, consider updating the library.",
                        severity=vuln["severity"], confidence="firm",
                        raw=item,
                        target_addrs=[asset_value],
                        meta_links=vuln["info"],
                        meta_tags=["js", "library", "update", "retire.js"],
                        meta_vuln_refs=item_vuln_refs)
                    issue_id+=1
                    findings.append(new_finding)

        # findings summary per asset (remove the workdir)
        checked_files_str = "\n".join([remove_prefix(ff, scan_wd_asset) for ff in sorted(checked_files)])

        summary_asset_finding_hash = hashlib.sha1(checked_files_str).hexdigest()[:6]
        summary_asset_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="code_js_summary",
            title="Retire.js scan summary for '{}' (#: {}, HASH: {})".format(
                asset_value, len(checked_files), summary_asset_finding_hash),
            description="Checked files:\n\n{}".format(checked_files_str),
            solution="n/a.",
            severity="info", confidence="firm",
            raw=checked_files,
            target_addrs=[asset_value],
            meta_tags=["js", "library", "retire.js"])
        issue_id+=1
        findings.append(summary_asset_finding)

    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] = engine.scans[scan_id]["findings"] + findings

    # Remove the workdir
    shutil.rmtree(scan_wd, ignore_errors=True)


def _scanowaspdc_thread(scan_id, asset_kw):
    issue_id = 0
    findings = []
    asset_values = [a["value"] for a in engine.scans[scan_id]["assets"]]

    # Create the scan's workdirs
    scan_wd = "{}/workdirs/scan_{}_{}".format(APP_BASE_DIR, scan_id, str(time.time()))
    if not os.path.exists(APP_BASE_DIR+"/workdirs"):
        os.makedirs(APP_BASE_DIR+"/workdirs")
    if not os.path.exists(scan_wd):
        os.makedirs(scan_wd)

    for asset_value in asset_values:
        checked_files = []
        # create the asset scan workdir
        scan_wd_asset = "{}/{}/src".format(scan_wd, hashlib.sha1(asset_value).hexdigest()[:6])
        os.makedirs(scan_wd_asset)

        #print "scan_wd_asset:", scan_wd_asset

        # Check location and copy files to the workdir
        if not _check_location(scan_id, asset_value, scan_wd_asset):
            # Generate an error if it was not possible to get the source code
            summary_asset_finding = PatrowlEngineFinding(
                issue_id=issue_id, type="code_ext_jar_summary",
                title="OWASP-DC scan not performed for '{}' (Error)".format(asset_value),
                description="Scan error with source code available at this location: '{}'. Unknwon error.".format(asset_value),
                solution="n/a.",
                severity="info", confidence="firm",
                raw={},
                target_addrs=[asset_value],
                meta_tags=["jar", "library", "owasp", "dependencies"])
            issue_id+=1
            findings.append(summary_asset_finding)
            continue

        time.sleep(2)

        # Start the scan
        cmd = 'libs/dependency-check/bin/dependency-check.sh --scan "{}" --format JSON --out "{}/oc_{}.json" --project "{}" --enableExperimental'.format(
            scan_wd_asset, scan_wd_asset, scan_id, scan_id)

        #print "cmd:", cmd

        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

        # Wait a little to ensure the report file is completely writen
        p.wait()
        time.sleep(2)

        report_filename = scan_wd_asset + "/oc_{}.json".format(scan_id)
        if not os.path.exists(report_filename):
            print("report file '{}' not found.".format(report_filename))

        scan_results = json.load(open(report_filename))

        for item in scan_results["dependencies"]:
            if "vulnerabilities" not in item.keys(): continue
            checked_files.append(item["filePath"])

            for vuln in item["vulnerabilities"]:

                vuln_name = ""
                if vuln["name"].isdigit():
                    vuln_name = "NSP-{}".format(vuln["name"])
                else:
                    vuln_name = vuln["name"]

                item_title = "External library '{}' vulnerable ({})".format(
                    item["fileName"], vuln_name)

                item_description = "Filepath: {}\nFilename: {}\n\n{}\n\nIdentifiers:\n{}".format(
                    remove_prefix(item["filePath"], scan_wd_asset),
                    item["fileName"],
                    vuln["description"].encode('utf-8').strip(),
                    "\n".join([ vs["software"] for vs in vuln["vulnerableSoftware"]])
                )

                vuln_risks = {}
                if "cvssScore" in vuln.keys() and vuln["cvssScore"] != "":
                    vuln_risks.update({"cvss_base_score": float(vuln["cvssScore"])})

                vuln_links = [v["url"] for v in vuln["references"]]

                vuln_refs = {}
                if "cwe" in vuln.keys() and vuln["cwe"] != "":
                    vuln_refs.update({"CWE": [vuln["cwe"].split(" ")[0]]})
                if vuln["name"].startswith("CVE-"):
                    vuln_refs.update({"CVE": [vuln["name"]]})

                new_finding = PatrowlEngineFinding(
                    issue_id=issue_id, type="code_ext_jar_missing_update",
                    title=item_title,
                    description=item_description,
                    solution="Check the exploitability of the vulnerability in the application context. If the vulnerability is verified, consider updating the library.",
                    severity=vuln["severity"].lower(), confidence="firm",
                    raw=vuln,
                    target_addrs=[asset_value],
                    meta_links=vuln_links,
                    meta_tags=["jar", "library", "update", "owasp", "dependencies"],
                    meta_risk=vuln_risks,
                    meta_vuln_refs=vuln_refs)
                issue_id+=1
                findings.append(new_finding)


        # findings summary per asset (remove the workdir)
        checked_files_str = "\n".join([remove_prefix(ff, scan_wd_asset) for ff in sorted(checked_files)])

        summary_asset_finding_hash = hashlib.sha1(checked_files_str).hexdigest()[:6]
        summary_asset_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="code_ext_jar_summary",
            title="OWASP-DC scan summary for '{}' (#: {}, HASH: {})".format(
                asset_value, len(checked_files), summary_asset_finding_hash),
            description="Checked files:\n\n{}".format(checked_files_str),
            solution="n/a.",
            severity="info", confidence="firm",
            raw=[remove_prefix(ff, scan_wd_asset) for ff in checked_files],
            target_addrs=[asset_value],
            meta_tags=["jar", "library", "owasp", "dependencies"])
        issue_id+=1
        findings.append(summary_asset_finding)

    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] = engine.scans[scan_id]["findings"] + findings

    # Remove the workdir
    shutil.rmtree(scan_wd, ignore_errors=True)


@app.before_first_request
def main():
    engine._loadconfig()


if __name__ == '__main__':
    engine.run_app(app_host=APP_HOST, app_port=APP_PORT)
