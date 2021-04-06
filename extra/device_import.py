import copy
import csv
import json
import uuid
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

insite = "172.16.112.14"

device_url = "https://{}/api/-/settings/device".format(insite)
logon_url = "https://{}/api/v1/login".format(insite)
logout_url = "https://{}/api/v1/logout".format(insite)
annotation_type_url = "https://{}/api/-/model/catalog/annotation/general-host-to-devicetype".format(
    insite
)
annotation_servicename_url = "https://{}/api/-/model/catalog/annotation/general-host-to-servicename".format(
    insite
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

if Path("_files/cbs_mediator_import.csv").exists():
    csv_file = Path("_files/cbs_mediator_import.csv")
elif Path("cbs_mediator_import.csv").exists():
    csv_file = Path("cbs_mediator_import.csv")

with open(csv_file, "r") as f:

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


def post(http_session, url, data):

    resp = http_session.post(
        url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(data),
        verify=False,
    )

    print("post", url, resp.status_code)

    return resp


def put(http_session, url, data):

    resp = http_session.put(
        url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(data),
        verify=False,
    )

    print("put", url, resp.status_code)

    return resp


def get(http_session, url):

    resp = http_session.get(
        url, headers={"Content-Type": "application/json;charset=UTF-8"}, verify=False,
    )

    print("get", url, resp.status_code)

    return json.loads(resp.text)


with requests.Session() as http_session:

    post(http_session, logon_url, {"username": "admin", "password": "admin"})

    device_db = get(http_session, device_url)

    device_db["devices"].extend(device_list)
    print(json.dumps(device_db, indent=1))

    post(http_session, device_url, device_db)

    annotation_type_db = get(http_session, annotation_type_url)
    annotation_type_db.update(annotation_type)
    put(http_session, annotation_type_url, annotation_type_db)

    annotation_servicename_db = get(http_session, annotation_servicename_url)
    annotation_servicename_db.update(annotation_servicename)
    put(http_session, annotation_servicename_url, annotation_servicename_db)
