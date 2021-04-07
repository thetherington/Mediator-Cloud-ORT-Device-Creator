import copy
import csv
import json
import uuid
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

INSITE = "172.16.112.14"
CSV_FILE = "cbs_mediator_import.csv"

DEVICE_URL = "https://{}/api/-/settings/device".format(INSITE)
LOGON_URL = "https://{}/api/v1/login".format(INSITE)
LOGOUT_URL = "https://{}/api/v1/logout".format(INSITE)
ANNOTATION_TYPE_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-devicetype".format(
    INSITE
)
ANNOTATION_SERVICENAME_URL = "https://{}/api/-/model/catalog/annotation/general-host-to-servicename".format(
    INSITE
)

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

if Path("_files/" + CSV_FILE).exists():
    csv_path = Path("_files/" + CSV_FILE)

elif Path(CSV_FILE).exists():
    csv_path = Path(CSV_FILE)

with open(csv_path, "r") as f:

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


with requests.Session() as http_session:

    post(http_session, LOGON_URL, {"username": "admin", "password": "admin"})

    device_db = get(http_session, DEVICE_URL)

    device_db["devices"].extend(device_list)
    print(json.dumps(device_db, indent=1))

    post(http_session, DEVICE_URL, device_db)

    annotation_type_db = get(http_session, ANNOTATION_TYPE_URL)
    annotation_type_db.update(annotation_type)
    put(http_session, ANNOTATION_TYPE_URL, annotation_type_db)

    annotation_servicename_db = get(http_session, ANNOTATION_SERVICENAME_URL)
    annotation_servicename_db.update(annotation_servicename)
    put(http_session, ANNOTATION_SERVICENAME_URL, annotation_servicename_db)
