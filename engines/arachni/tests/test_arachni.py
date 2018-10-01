import sys, os
import json, requests, time, random

sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
from utils.PatrowlEngineTest import PatrowlEngineTest

# Define the engine instance
pet = PatrowlEngineTest(engine_name="arachni", base_url="http://127.0.0.1:5005/engines/arachni")

# generic tests
def test_generic_features():
    pet.do_generic_tests()

## custom tests
def test_arachni_xss():
    pet.custom_test(
        test_name="arachni_xss",
        assets=[{
            "id" :'1',
            "value" :'https://xss-game.appspot.com/level1',
            "criticity": 'high',
            "datatype": 'url'
        }],
        scan_policy={
            "max_timeout": 300,
            "no_fingerprinting" : True,
            "http": {
                "user_agent": "Arachni/v2.0dev-FullScan",
                #"request_queue_size" : 200,
                "request_queue_size" : 1000,
                "request_redirect_limit" : 5,
                #"request_concurrency" : 10
                "request_concurrency" : 30
            },
            "input" : {
                "values" : {},
                "without_defaults" : True,
                "force" : False
            },
            "browser_cluster": {
                "pool_size": 12,
                "ignore_images": True,
                "job_timeout" : 10,
                "worker_time_to_live" : 100,
            },
            "scope": {
                "exclude_file_extensions": ['pdf', 'css', 'ico', 'jpg', 'svg', 'png', 'gif', 'jpeg'],
                "auto_redundant_paths": 10,
                "include_subdomains": False,
                "exclude_binaries": True,
                "exclude_binaries": False,
                "https_only" : False
            },
            "audit": {
                "parameter_values": True,
                "exclude_vector_patterns": [],
                "include_vector_patterns": [],
                "link_templates": [],
                "links": True,
                "forms": True,
                "cookies": False,
                #"headers" : True,
                "headers" : False,
                "with_both_http_methods" : False,
                "jsons": True,
                "xmls": True,
                "ui_forms": True,
                "ui_inputs": True
            },
            "checks": [
                # "allowed_methods",
                # "backdoors",
                # "backup_directories",
                # "backup_files",
                # #"captcha",
                # "code_injection",
                # "code_injection_php_input_wrapper",
                # "code_injection_timing",
                # "common_admin_interfaces",
                # "common_directories",
                # "common_files",
                # "cookie_set_for_parent_domain",
                # #"credit_card",
                # "csrf",
                # "cvs_svn_users",
                # "directory_listing",
                # #"emails",
                # "file_inclusion",
                # #"form_upload",
                # "hsts",
                # "htaccess_limit",
                # #"html_objects",
                # "http_only_cookies",
                # "http_put",
                # "insecure_client_access_policy",
                # "insecure_cookies",
                # "insecure_cors_policy",
                # "insecure_cross_domain_policy_access",
                # "insecure_cross_domain_policy_headers",
                # #"interesting_responses",
                # "ldap_injection",
                # "localstart_asp",
                # "mixed_resource",
                # "no_sql_injection",
                # "no_sql_injection_differential",
                # "origin_spoof_access_restriction_bypass",
                # "os_cmd_injection",
                # "os_cmd_injection_timing",
                # "password_autocomplete",
                # "path_traversal",
                # "private_ip",
                # "response_splitting",
                # "rfi",
                # "session_fixation",
                # "source_code_disclosure",
                # "sql_injection",
                # "sql_injection_differential",
                # "sql_injection_timing",
                # #"ssn",
                # "trainer",
                # "unencrypted_password_forms",
                # "unvalidated_redirect",
                # "unvalidated_redirect_dom",
                # "webdav",
                # "x_frame_options",
                # "xpath_injection",
                "xss",
                "xss_dom",
                "xss_dom_script_context",
                "xss_event",
                "xss_path",
                "xss_script_context",
                "xss_tag",
                #"xst",
                "xxe"
              ]
        },
        is_valid=True
    )


if __name__ == '__main__':
    sleep(5)
    test_generic_features()
    test_arachni_xss()
