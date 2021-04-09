import argparse
import json
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


def post(session, url, data):

    resp = session.post(
        url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(data),
        verify=False,
    )

    print("post", url, resp.status_code)

    return resp


def get(session, url):

    resp = session.get(
        url, headers={"Content-Type": "application/json;charset=UTF-8"}, verify=False,
    )

    print("get", url, resp.status_code)

    return json.loads(resp.text)


parser = argparse.ArgumentParser(description="inSITE Ping Poller Host Importer Tool")
parser.add_argument(
    "-H",
    "--host",
    metavar="",
    required=False,
    default="127.0.0.1",
    help="IP to inSITE Server (default 127.0.0.1)",
)
parser.add_argument(
    "-P",
    "--poller",
    metavar="",
    required=False,
    default="ping",
    help="Name of the ping collector (default ping)",
)

args = parser.parse_args()
# args = parser.parse_args(["-H", "172.16.112.14"])

INSITE = args.host
COLLECTOR = args.poller
LOGON_URL = "https://{}/api/v1/login".format(INSITE)
LOGOUT_URL = "https://{}/api/v1/logout".format(INSITE)
POLLERS_URL = "https://{}/proxy/insite/pll-1/api/-/model/pollers".format(INSITE)
POLLER_URL = "https://{}/proxy/insite/pll-1/api/-/model/poller/".format(INSITE)
ANNOTATION_NAME_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-devicename".format(
    INSITE
)
# regex pattern to match for valid ip in string like: ip-192.168.10.1
HOSTNAME_PATTERN = re.compile(
    r"ip-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)

with requests.Session() as http_session:

    post(http_session, LOGON_URL, {"username": "admin", "password": "admin"})

    pollers = get(http_session, POLLERS_URL)
    annotations = get(http_session, ANNOTATION_NAME_URL)

    for poller in pollers["pollers"]:

        if poller["identification"]["name"].lower() == COLLECTOR.lower():

            POLLER_URL += poller["identification"]["uid"]

            # iterate through each match (ip-xxx-xxx-xxx-xxx) from the annotation json
            # and join all the octet groups together to form a valid ip address.
            poller["input"]["hosts"] = [
                ".".join(match.groups()) for match in HOSTNAME_PATTERN.finditer(str(annotations))
            ]

            print("Hosts:", len(poller["input"]["hosts"]))
            print(poller)

            post(http_session, POLLER_URL, {"poller": poller})
            post(http_session, LOGOUT_URL, {})

            break
    else:
        print("No pollers were updated.", "Check if the ping poller exists:", args.poller)
