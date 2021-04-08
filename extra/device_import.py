import argparse
import copy
import csv
import json
import uuid
from itertools import product
from pathlib import Path

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


def put(session, url, data):

    resp = session.put(
        url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(data),
        verify=False,
    )

    print("put", url, resp.status_code)

    return resp


def get(session, url):

    resp = session.get(
        url, headers={"Content-Type": "application/json;charset=UTF-8"}, verify=False,
    )

    print("get", url, resp.status_code)

    return json.loads(resp.text)


def remove_duplicate_devices(x_list, y_db):

    y_count, x_count = len(y_db), len(x_list)

    for y, x in product(y_db, x_list):

        x_matchables = set(x["identification"]["matchables"])
        y_matchables = set(y["identification"]["matchables"])
        x_tags = set(x["grouping"]["tags"])
        y_tags = set(y["grouping"]["tags"])

        if x["identification"]["alias"] == y["identification"]["alias"]:

            # if this tests true, then the newly created one matches exactly as the one in insite
            if (x_matchables == y_matchables) and (x_tags == y_tags):
                x_list.remove(x)

            # XOR test. if one is true and other is false, then a change has happened to an existing device
            elif (x_matchables == y_matchables) ^ (x_tags == y_tags):
                y_db.remove(y)

    # return counts
    return (x_count - len(x_list)), (y_count - len(y_db))


parser = argparse.ArgumentParser(description="inSITE device importer tool")
parser.add_argument(
    "-H", "--host", metavar="", required=False, default="127.0.0.1", help="IP to inSITE Server",
)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-F", "--file", metavar="", required=False, help="CSV File to Import")
group.add_argument(
    "-D",
    "--dump",
    required=False,
    action="store_true",
    help="Clear out existing device and annotations",
)

args = parser.parse_args()
# args = parser.parse_args(["-H", "172.16.112.14", "-F", "_files/cbs_mediator_import.csv"])
# args = parser.parse_args(["-H", "172.16.112.14", "-D"])

INSITE = args.host
CSV_FILE = args.file

DEVICE_URL = "https://{}/api/-/settings/device".format(INSITE)
LOGON_URL = "https://{}/api/v1/login".format(INSITE)
LOGOUT_URL = "https://{}/api/v1/logout".format(INSITE)
ANNOTATION_NAME_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-devicename".format(
    INSITE
)
ANNOTATION_TYPE_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-devicetype".format(
    INSITE
)
ANNOTATION_SERVICENAME_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-servicename".format(
    INSITE
)

if args.dump:

    with requests.Session() as http_session:

        print("Cleaning devices and annotations...")

        post(http_session, LOGON_URL, {"username": "admin", "password": "admin"})
        post(http_session, DEVICE_URL, {})
        put(http_session, ANNOTATION_NAME_URL, {})
        put(http_session, ANNOTATION_TYPE_URL, {})
        put(http_session, ANNOTATION_SERVICENAME_URL, {})

    if not args.file:
        quit()


device_template = {
    "identification": {
        "uid": None,
        "alias": None,
        "matchables": [],
        "restrictable-ips": [""],
        "control-ips": [],
    },
    "grouping": {"tags": []},
}

device_list = []
annotation_type = {}
annotation_servicename = {}

if Path(CSV_FILE).exists():
    csv_path = Path(CSV_FILE)

else:
    print("Invalid CSV File/Path " + CSV_FILE)
    quit()

with open(str(csv_path), "r") as f:

    reader = csv.reader(filter(lambda row: row[0] != "#", f))

    for row in reader:

        if len(row) > 0:

            device = copy.deepcopy(device_template)

            device["identification"]["uid"] = str(uuid.uuid4())
            device["identification"]["alias"] = row[0]
            device["identification"]["matchables"].extend(row[1].split(";"))
            device["identification"]["control-ips"].extend(row[1].split(";"))

            device["grouping"]["tags"].extend(row[4].split(";"))

            device_list.append(device)

            for match in device["identification"]["matchables"]:
                annotation_type.update({match: device["grouping"]["tags"][1]})
                annotation_servicename.update({match: device["grouping"]["tags"][2]})


with requests.Session() as http_session:

    post(http_session, LOGON_URL, {"username": "admin", "password": "admin"})

    device_db = get(http_session, DEVICE_URL)
    print("Fetched %s Devices" % (len(device_db["devices"])))

    count_x, count_y = remove_duplicate_devices(device_list, device_db["devices"])
    _ = [print(x) for x in device_list]
    print("Dropped %s from db" % (count_y), "Dropped %s from csv" % (count_x))

    device_db["devices"].extend(device_list)
    print("Posting %s Devices" % (len(device_db["devices"])))
    post(http_session, DEVICE_URL, device_db)

    annotation_type_db = get(http_session, ANNOTATION_TYPE_URL)
    annotation_type_db.update(annotation_type)
    put(http_session, ANNOTATION_TYPE_URL, annotation_type_db)

    annotation_servicename_db = get(http_session, ANNOTATION_SERVICENAME_URL)
    annotation_servicename_db.update(annotation_servicename)
    put(http_session, ANNOTATION_SERVICENAME_URL, annotation_servicename_db)
