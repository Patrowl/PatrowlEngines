#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Owl_Leaks PatrOwl engine application.

Known ratio:
- Github searches: 30 per minute
- Twitter: 450 per 15-min window
"""

import os
import time
import threading
from flask import Flask, request, jsonify
from github import Github
from twitter import Twitter, OAuth
import hashlib

from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions

APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5012
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 25))
APP_SEARCH_TWITTER_MAX_COUNT_DEFAULT = 100
APP_ENGINE_NAME = "owl_leaks"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
VERSION = "1.4.18"

app = Flask(__name__)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS,
    version=VERSION
)


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


@app.route('/')
def default():
    """Route by default."""
    return engine.default()


@app.route('/engines/owl_leaks/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/owl_leaks/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/owl_leaks/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/owl_leaks/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/owl_leaks/reloadconfig')
def reloadconfig():
    """Reload the configuration file."""
    return engine.reloadconfig()


@app.route('/engines/owl_leaks/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/owl_leaks/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/owl_leaks/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/owl_leaks/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/owl_leaks/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.getstatus_scan(scan_id)


@app.route('/engines/owl_leaks/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/owl_leaks/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/owl_leaks/getfindings/<scan_id>')
def getfindings(scan_id):
    """Get findings on finished scans."""
    return engine.getfindings(scan_id)


@app.route('/engines/owl_leaks/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


@app.route('/engines/owl_leaks/startscan', methods=['POST'])
def start_scan():
    """Start a new scan."""
    # Check params and prepare the PatrowlEngineScan
    res = engine.init_scan(request.data)
    if "status" in res.keys() and res["status"] != "INIT":
        return jsonify(res)

    scan_id = res["details"]["scan_id"]

    if engine.had_options("github_api_token") and "search_github" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["search_github"] is True:
        for asset in engine.scans[scan_id]["assets"]:
            th = threading.Thread(target=_search_github_thread, args=(scan_id, asset["value"],))
            th.start()
            engine.scans[scan_id]['threads'].append(th)

    if engine.had_options(["twitter_oauth_token", "twitter_oauth_secret", "twitter_consumer_key", "twitter_consumer_secret"]) and "search_twitter" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["search_twitter"] is True:
        for asset in engine.scans[scan_id]["assets"]:
            th = threading.Thread(target=_search_twitter_thread, args=(scan_id, asset["value"],))
            th.start()
            engine.scans[scan_id]['threads'].append(th)

    engine.scans[scan_id]['status'] = "SCANNING"

    # Finish
    res.update({"status": "accepted"})
    return jsonify(res)


def _search_github_thread(scan_id, asset_kw):

    issue_id = 0
    findings = []
    asset_values = [a["value"] for a in engine.scans[scan_id]["assets"]]

    # qualifiers={}
    # if "github_qualifiers" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["github_qualifiers"] is not None:
    #     for opt_qualifier in engine.scans[scan_id]["options"]["github_qualifiers"].keys():
    #         if opt_qualifier == "since_period":
    #             num = re.search(r'\d+', engine.scans[scan_id]["options"]["github_qualifiers"]["since_period"]).group()
    #             unit = re.search(r'[a-zA-Z]+', engine.scans[scan_id]["options"]["github_qualifiers"]["since_period"]).group()
    #             if unit in ["weeks", "days", "hours", "minutes", "seconds"]:
    #                 since_date=date.today()-timedelta(**pa)
    #                 qualifiers.update({"created": ">="+str(since_date)})
    #         elif opt_qualifier == "from_date":
    #             try:
    #                 from_date_str = engine.scans[scan_id]["options"]["github_qualifiers"]["from_date"]
    #                 from_date_check = datetime.strptime(engine.scans[scan_id]["options"]["github_qualifiers"]["from_date"], "%Y-%m-%d")
    #                 qualifiers.update({"created": ">="+str(from_date_str)})
    #             except Exception:
    #                 print "bad datetime format"
    #
    #         elif opt_qualifier == "to_date":
    #             try:
    #                 to_date_str = engine.scans[scan_id]["options"]["github_qualifiers"]["to_date"]
    #                 to_date_check = datetime.strptime(engine.scans[scan_id]["options"]["github_qualifiers"]["to_date"], "%Y-%m-%d")
    #                 qualifiers.update({"created": "<="+str(to_date_str)})
    #             except Exception:
    #                 print "bad datetime format"

    # g = Github(engine.options["github_username"], engine.options["github_password"])  # rate limit = 30 requests/min
    g = Github(engine.options["github_api_token"])

    loops = 0
    for git_code in g.search_code("\'"+asset_kw+"\'", sort="indexed", order="desc"):
        ititle = "File found in Github public repo (code): {}/{} (HASH: {})".format(
            git_code.name,
            git_code.repository.name, git_code.sha[:6])
        iemail = ""
        if git_code.repository.owner.email is not None:
            git_code.repository.owner.email.encode("ascii", "ignore")
        idescription = "File found in Github public repo (code):\n\n" + \
            "URL: {}\n\n".format(git_code.html_url) + \
            "Repo: {}: \n\n".format(git_code.repository.name, git_code.repository.url) + \
            "Owner:\nlogin:{}, name:{}, email:{}\n\n".format(
                git_code.repository.owner.login,
                git_code.repository.owner.name,
                iemail) + \
            "Content ({} bits):{}".format(git_code.size, git_code.decoded_content)
        isolution = "Check if the snippet is legit or not. " + \
            "If not, see internal procedures for incident reaction."
        issue_id += 1

        new_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="github_leak_code", title=ititle,
            description=idescription, solution=isolution, severity="high",
            confidence="firm", raw=git_code.raw_data, target_addrs=asset_values,
            meta_links=[git_code.html_url])
        findings.append(new_finding)

        # Ratio limit trick: wait 3 seconds each 20 iters
        loops += 1
        if loops % 20 == 0:
            time.sleep(3)

    # for git_commit in g.search_commits("\'"+asset_kw+"\'", sort="indexed", order="desc"):
    #     print dir(git_commit)

    for git_issue in g.search_issues("\'"+asset_kw+"\'", sort="updated", order="desc"):
        ititle = "Matching issue found in Github public repo: {}... (HASH: {})".format(
            git_issue.title[:16],
            hashlib.sha1(str(git_issue.body).encode('utf-8')).hexdigest()[:6])
        idescription = "Matching issue found in Github public repo:\n\n" + \
            "URL: {}\n\n".format(git_issue.html_url) + \
            "Repo: {}: \n\n".format(git_issue.repository.name, git_issue.repository.url) + \
            "Owner:\nlogin:{}, name:{}, email:{}\n\n".format(
                git_issue.repository.owner.login,
                git_issue.repository.owner.name,
                git_issue.repository.owner.email) + \
            "Content: {}".format(git_issue.body)
        isolution = "Check if the snippet is legit or not. " + \
            "If not, see internal procedures for incident reaction."
        issue_id += 1

        new_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="github_leak_issue", title=ititle,
            description=idescription, solution=isolution, severity="high",
            confidence="firm", raw=git_issue.raw_data, target_addrs=asset_values,
            meta_links=[git_issue.html_url])
        findings.append(new_finding)

    for git_repo in g.search_repositories("\'"+asset_kw+"\'", sort="updated", order="desc"):
        ititle = "Matching public Github repo: {} (HASH: {})".format(
            git_repo.name,
            hashlib.sha1(git_repo.description.encode('ascii', 'ignore')).hexdigest()[:6])
        idescription = "Matching public Github repo:\n\n" + \
            "URL: {}\n\n".format(git_repo.html_url) + \
            "Repo: {}: \n\n".format(git_repo.name, git_repo.url) + \
            "Owner:\nlogin:{}, name:{}, email:{}\n\n".format(
                git_repo.owner.login,
                git_repo.owner.name,
                git_repo.owner.email) + \
            "Content: {}".format(git_repo.description.encode('ascii', 'ignore'))
        isolution = "Check if the snippet is legit or not. " + \
            "If not, see internal procedures for incident reaction."
        issue_id += 1

        new_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="github_leak_repo", title=ititle,
            description=idescription, solution=isolution, severity="high",
            confidence="firm", raw=git_repo.raw_data, target_addrs=asset_values,
            meta_links=[git_repo.html_url])
        findings.append(new_finding)

    for git_user in g.search_users(asset_kw, sort="joined", order="desc"):
        ititle = "Matching Github user: {} (HASH: {})".format(
            git_user.login,
            hashlib.sha1(str(git_user.login).encode('utf-8')).hexdigest()[:6])
        ibio = ""
        if git_user.bio:
            ibio = git_user.bio.encode('ascii', 'ignore')
        idescription = "Matching Github user:\n\n" + \
            "URL: {}\n\n".format(git_user.html_url) + \
            "Info:\nlogin:{}, name:{}, email:{}\n\n".format(
                git_user.login,
                git_user.name.encode('ascii', 'ignore'),
                git_user.email) + \
            "Bio: {}".format(ibio)
        isolution = "Check if the user is legit or not. " + \
            "If not, see internal procedures for incident reaction."
        issue_id += 1

        new_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="github_leak_user", title=ititle,
            description=idescription, solution=isolution, severity="high",
            confidence="firm", raw=git_user.raw_data, target_addrs=asset_values,
            meta_links=[git_user.html_url])
        findings.append(new_finding)

    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] = engine.scans[scan_id]["findings"] + findings


def _search_twitter_thread(scan_id, asset_kw):

    issue_id = 0
    findings = []
    twitter = Twitter(
        auth=OAuth(
            engine.options["twitter_oauth_token"], engine.options["twitter_oauth_secret"],
            engine.options["twitter_consumer_key"], engine.options["twitter_consumer_secret"]
        ),
        retry=True
    )


    # Set the Max count
    max_count = APP_SEARCH_TWITTER_MAX_COUNT_DEFAULT
    extra_kw = ""
    since = ""
    if "search_twitter_options" in engine.scans[scan_id]["options"].keys() and engine.scans[scan_id]["options"]["search_twitter_options"] is not None:
        if "max_count" in engine.scans[scan_id]["options"]["search_twitter_options"].keys() and engine.scans[scan_id]["options"]["search_twitter_options"]["max_count"] is not None and isinstance(engine.scans[scan_id]["options"]["search_twitter_options"]["max_count"], int):
            max_count = engine.scans[scan_id]["options"]["search_twitter_options"]["max_count"]
        if "extra_kw" in engine.scans[scan_id]["options"]["search_twitter_options"].keys() and engine.scans[scan_id]["options"]["search_twitter_options"]["extra_kw"] is not None and isinstance(engine.scans[scan_id]["options"]["search_twitter_options"]["extra_kw"], list):
            extra_kw = " OR ".join(engine.scans[scan_id]["options"]["search_twitter_options"]["extra_kw"])
        if "since" in engine.scans[scan_id]["options"]["search_twitter_options"].keys() and engine.scans[scan_id]["options"]["search_twitter_options"]["since"] is not None and isinstance(engine.scans[scan_id]["options"]["search_twitter_options"]["since"], str):
            since = "since:{}".format(engine.scans[scan_id]["options"]["search_twitter_options"]["since"])

    # WARNING a query should not exceed 500 chars, including filters and operators
    # print "query_string :", "\""+asset_kw+"\" "+extra_kw+" "+since+" -filter:retweets", "len:", len("\""+asset_kw+"\" "+extra_kw+" "+since+" -filter:retweets")
    results = twitter.search.tweets(q="\""+asset_kw+"\" "+extra_kw+" -filter:retweets", count=max_count)
    # print results

    if len(results["statuses"]) == 0:  # no results
        metalink = "https://twitter.com/search"+results["search_metadata"]["refresh_url"]
        new_finding = PatrowlEngineFinding(
            issue_id=issue_id, type="twitter_leak",
            title="No matching tweets.",
            description="No matching tweet with following parameters:\n" + \
                "Keyword (strict): {}\n".format(asset_kw) + \
                "Extra key words: {}\n".format(extra_kw) + \
                "URL: {}\n".format(metalink),
            solution="N/A",
            severity="info", confidence="firm",
            raw=results,
            target_addrs=[asset_kw],
            meta_links=[metalink])
        findings.append(new_finding)

    else:
        for tweet in results["statuses"]:
            # print "id:", tweet["id"], "text:", tweet["text"]
            # print "user_id:", tweet["user"]["id"], "user_name:", tweet["user"]["name"], "user_nickname:", tweet["user"]["screen_name"]
            # print "tweet_url:", "https://twitter.com/i/web/status/"+tweet["id_str"]

            issue_id += 1
            tw_hash = hashlib.sha1(str(tweet["text"]).encode('utf-8')).hexdigest()[:6]

            metalink = "https://twitter.com/search"+results["search_metadata"]["refresh_url"]
            new_finding = PatrowlEngineFinding(
                issue_id=issue_id, type="twitter_leak",
                title="Tweet matching search query (HASH: {}).".format(tw_hash),
                description="A tweet matching monitoring keywords has been found:\n" + \
                    "Query options:\nKeyword (strict): {}\n".format(asset_kw) + \
                    "Extra key words: {}\n".format(extra_kw) + \
                    "URL: {}\n".format(metalink),
                solution="Evaluate criticity. See internal procedures for incident reaction.",
                severity="high", confidence="firm",
                raw=tweet,
                target_addrs=[asset_kw],
                meta_links=[metalink])
            findings.append(new_finding)

    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] = engine.scans[scan_id]["findings"] + findings


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR+"/results"):
        os.makedirs(APP_BASE_DIR+"/results")
    engine._loadconfig()


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
