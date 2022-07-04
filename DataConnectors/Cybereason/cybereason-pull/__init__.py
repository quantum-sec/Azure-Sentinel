import base64
import hashlib
import hmac
import json
import logging
import os
import re
import requests

from delorean import Delorean
from datetime import datetime, timedelta
import azure.functions as func

customer_id = os.environ["WorkspaceID"]
shared_key = os.environ["WorkspaceKey"]
username = os.environ["CybereasonUserName"]
password = os.environ["CybereasonPassword"]
hostname = os.environ["CybereasonHostName"]


port = "443"

base_url = "https://" + hostname + ":" + port
malops_endpoint = "/rest/detection/inbox"
malop_details_endpoint = "/rest/detection/details"

connection_string = os.environ["AzureWebJobsStorage"]
logAnalyticsUri = os.environ.get("logAnalyticsUri")


def check_log_analytics_uri(logAnalyticsUri):
    if logAnalyticsUri in (None, "") or str(logAnalyticsUri).isspace():
        logAnalyticsUri = "https://" + customer_id + ".ods.opinsights.azure.com"

    pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
    match = re.match(pattern, str(logAnalyticsUri))
    if not match:
        raise Exception("Cybereason: Invalid Log Analytics Uri.")
    return logAnalyticsUri


session = requests.session()


def generate_session():
    data = {"username": username, "password": password}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    login_url = base_url + "/login.html"
    try:
        session.post(login_url, data=data, headers=headers, verify=True)
    except Exception as get_detections:
        logging.error("Error while login => : {}".format(get_detections))
        exit(1)
    return session


def get_detections(start_time, end_time):
    malops_url = base_url + malops_endpoint
    query = {"startTime": start_time, "endTime": end_time}

    headers = {"Content-Type": "application/json"}
    generate_session()
    try:
        malops = session.request(
            "POST", malops_url, data=json.dumps(query), headers=headers
        )
        detections = json.loads(malops.content)
    except Exception as get_detections:
        logging.error("Error getting detections => : {}".format(get_detections))
        exit(1)
    return detections


## Add this to get more details for Malop Detections
def get_detection_details(malopGuid):
    details = {}
    malop_details_url = base_url + malop_details_endpoint
    query = {"malopGuid": malopGuid}
    headers = {"Content-Type": "application/json"}
    generate_session()
    try:
        malop_details = session.request(
            "POST", malop_details_url, data=json.dumps(query), headers=headers
        )
        if malop_details.content:
            details = json.loads(malop_details.content)
        else:
            logging.info("No Malop Details")
            details = None
    except Exception as get_malop_details:
        logging.error(f"Error getting detections Details => : {get_malop_details}")
    return details


def generate_date():
    current_time = datetime.utcnow()
    past_time = current_time - timedelta(minutes=60)
    return (int(Delorean(past_time, timezone='UTC').epoch * 1000), (int(Delorean(current_time, timezone='UTC').epoch * 1000)))


def build_signature(
    customer_id, shared_key, date, content_length, method, content_type, resource
):
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(customer_id, shared_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = build_signature(
        customer_id,
        shared_key,
        rfc1123date,
        content_length,
        method,
        content_type,
        resource,
    )
    x = logAnalyticsUri
    x = check_log_analytics_uri(logAnalyticsUri)
    uri = x + resource + "?api-version=2016-04-01"
    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }
    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 200 and response.status_code <= 299:
        logging.info("Logs with {} activity was processed into Azure".format(log_type))
    else:
        logging.info("Response code: {}".format(response.status_code))


def main(timer: func.TimerRequest) -> None:
    utc_timestamp = datetime.utcnow().isoformat()
    if timer.past_due:
        logging.info("The timer is past due!")
    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    start_time, end_time = generate_date()
    malops = get_detections(start_time, end_time)
    if len(malops["malops"]) > 0:
        logging.info("Found Detections")
        for detection in malops["malops"]:
            post_data(customer_id, shared_key, json.dumps(detection), "CybereasonMalop")
            details = get_detection_details(detection["guid"])
            if details:
              post_data(
                  customer_id, shared_key, json.dumps(details), "CybereasonMalopDetail"
              )
    else:
        logging.info("No latest events available")
