#!/usr/bin/python3
import datetime
import requests
import json
import yaml
import logging
import os
import smtplib
from jinja2 import Environment, FileSystemLoader
from email.message import EmailMessage


class AuthenticationError(Exception):
    pass

# Configure logging.
logger = logging.getLogger()
logger.setLevel(logging.ERROR) # Default logging value is ERROR. Could be changed to "logging.DEBUG"

# Set console handler
ch = logging.StreamHandler()
formatter = logging.Formatter(
    "%(threadName)s %(asctime)s %(name)s %(levelname)s: %(message)s"
)
ch.setFormatter(formatter)

# Add handler to logger
logger.addHandler(ch)

# Login function. It is used if we fail to connect to F5CS API with existing Access Token and Refresh Token
def login(username, password):
    login_url = "https://api.cloudservices.f5.com/v1/svc-auth/login"
    login_data = {"username": username, "password": password}
    login_headers = {'Content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate, br',
                     'Connection': 'keep-alive'}
    logger.debug("Login function. Issuing login request to https://api.cloudservices.f5.com/v1/svc-auth/login. \
                     We need to authenticate with Username and Password to get the Access Token and Refresh Token")


    login_request = requests.post(login_url, data=json.dumps(login_data), headers=login_headers)

    if login_request.status_code == 400 and "Incorrect username or password" in login_request.json()["error"]:
        logger.error("Can't authenticate to https://api.cloudservices.f5.com/v1/svc-auth/login. Incorrect username or password.")
        raise AuthenticationError("Can't authenticate to https://api.cloudservices.f5.com/v1/svc-auth/login. Incorrect username or password.")

    elif login_request.status_code == 200:
        logger.debug("Login function. Received the Access Token")

        access_token = login_request.json()["access_token"]
        with open('tokens.yaml', 'w') as tokens_file:
            yaml.dump(login_request.json(), tokens_file, default_flow_style=False)
        return access_token

# Re-login function. It is used to get new Access Token, once the existing one expires
def relogin(username, refresh_token):
    relogin_url = "https://api.cloudservices.f5.com/v1/svc-auth/relogin"
    relogin_data = {"username": username, "refresh_token": refresh_token}
    relogin_headers = {'Content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate, br',
                       'Connection': 'keep-alive'}
    logger.debug("Relogin function. Issuing relogin request to https://api.cloudservices.f5.com/v1/svc-auth/relogin. \
                 We have Refresh Token and need to exchange it for Access Token.")

    relogin_request = requests.post(relogin_url, data=json.dumps(relogin_data), headers=relogin_headers)
    if relogin_request.status_code == 400 and "Failed to re-login." in relogin_request.json()["error"]:
        logger.debug("Relogin function. Can't re-authenticate to https://api.cloudservices.f5.com/v1/svc-auth/relogin.\
                    Refresh token expired. Calling Login function")

        access_token = login(username, password)
        return access_token

    elif relogin_request.status_code == 200:
        logger.debug("Relogin function. Received the Access Token")

        access_token = relogin_request.json()["access_token"]
        tokens_dict = {"access_token":access_token,"refresh_token": refresh_token}
        with open('tokens.yaml', 'w') as tokens_file:
            yaml.dump(tokens_dict, tokens_file, default_flow_style=False)
        return access_token

# Function to retrieve security events.
def get_security_incidents(service_instance_id, subscription_id, time_since, time_until, access_token):
    sec_incidents_data = {
        "service_instance_id": service_instance_id,
        "subscription_id": subscription_id,
        "since": time_since,
        "until:": time_until
    }
    sec_incidents_url = "https://api.cloudservices.f5.com/waf/v1/analytics/security/events"
    sec_incidents_headers = {'Content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate, br',
                             'Connection': 'keep-alive', 'Authorization': f'Bearer {access_token}'}

    logger.debug("Get Security Incidents function. Querying https://api.cloudservices.f5.com/waf/v1/analytics/security/events.\
                        Refresh token expired. Calling Login function")

    sec_incidents_request = requests.post(sec_incidents_url, data=json.dumps(sec_incidents_data), headers=sec_incidents_headers)
    if sec_incidents_request.status_code == 401:
        access_token = relogin(username, refresh_token)
        sec_incidents_headers = {'Content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate, br',
                                 'Connection': 'keep-alive', 'Authorization': f'Bearer {access_token}'}
        sec_incidents_request = requests.post(sec_incidents_url, data=json.dumps(sec_incidents_data), headers=sec_incidents_headers)

    return sec_incidents_request.json()


def generate_html_email_body(template, data_dict):
    loader=FileSystemLoader('')
    env = Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)
    template = env.get_template(template)
    output = template.render(data_dict)
    return output


# Initial variables
# Import F5 Cloud Services username and password from system variables
username = os.environ.get('USERNAME')
password = os.environ.get('PASSWORD')

# service_instance_id and subscription_id are unique values for each EAP application
# See https://clouddocs.f5.com/cloud-services/latest/f5-cloud-services-Essential.App.Protect-API.UsersGuide.html for more details
service_instance_id = "" # should be set to your EAP service_instance_id value
subscription_id = "" # should be set to your EAP subscription_id value
app_name = "" # Application Display name

# Import email and password from system variables
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

# Try to import Access and Refresh Tokens. If they don't exist, then log in using username/password
try:
    logger.debug("Trying to load Access Token and Refresh Token from 'tokens.yaml'")
    with open('tokens.yaml', 'r') as tokens_f:
        data = yaml.safe_load(tokens_f)
        access_token = data['access_token']
        refresh_token = data['refresh_token']

except (KeyError, FileNotFoundError):
    logger.debug("There are no ACCESS_TOKEN and REFRESH_TOKEN in Environment Variables")
    access_token = login(username, password)

# Get security incidents for the last 5 minutes. To get events for the minute set "datetime.timedelta(0,60)"
# For some reason, time in Portal and retrieved via API differs in 1 hour
# For example, in Portal event is logged at 09:32:00. The same event has time 08:32:00 via API
# Because of that I have to subtract 1 hour: (datetime.datetime.now() - datetime.timedelta(0,3600))
time_until = (datetime.datetime.now() - datetime.timedelta(0,3600)).strftime("%Y-%m-%dT%H:%M:%SZ")
time_since = (datetime.datetime.now() - datetime.timedelta(0,14400)).strftime("%Y-%m-%dT%H:%M:%SZ")

security_incidents = get_security_incidents(service_instance_id, subscription_id, time_since, time_until, access_token)

sec_inc_items = []
if len(security_incidents['events']) > 0:
    i = 0
    for sec_incident in security_incidents['events']:
        if i >= 20:
            break
        jinja_item_dict = {}

        # Change time format
        inc_time = datetime.datetime.strptime(sec_incident.pop('date_time', None), "%Y-%m-%dT%H:%M:%SZ")
        jinja_item_dict["date_time"] = inc_time.strftime("%b %d, %Y/%H:%M:%S")

        jinja_item_dict["uri"] = sec_incident.pop('uri', None)
        jinja_item_dict["severity"] = sec_incident.pop('severity', None)
        jinja_item_dict["detection_events"] = ", ".join(sec_incident.pop('detection_events', None))
        jinja_item_dict["attack_types"] = ", ".join(sec_incident.pop('attack_types', None))
        jinja_item_dict["request_status"] = sec_incident.pop('request_status', None)
        jinja_item_dict["source_ip"] = sec_incident.pop('source_ip', None)
        jinja_item_dict["geo_country"] = sec_incident.pop('geo_country', None).title()
        sec_inc_items.append(jinja_item_dict)
        i += 1

# Send email only if there were security incidents
if len(sec_inc_items) > 0:
    # Generate HTML body based on jinja2 template
    jinja_dict = {}
    jinja_dict['app_name'] = app_name
    jinja_dict['sec_inc_items'] = sec_inc_items
    TEMPLATE_FILE = 'jinja_table_1.html'
    sec_incidents_html = generate_html_email_body(TEMPLATE_FILE, jinja_dict)

    # Construct email
    msg = EmailMessage()
    msg['Subject'] = f'Attack detected for {app_name}'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = '' # email recipient
    msg.add_alternative(sec_incidents_html, subtype='html')

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)
