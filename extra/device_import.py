import copy
import csv
import json
import uuid

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

with open("_files\\cbs_mediator_import.csv", "r") as f:

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

            annotation_type.update({row[1]: device["grouping"]["tags"][1]})

            for match in device["identification"]["matchables"]:
                annotation_servicename.update({match: device["grouping"]["tags"][2]})

# print(json.dumps(device_list, indent=1))

with requests.Session() as http_session:

    resp = http_session.post(
        logon_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps({"username": "admin", "password": "admin"}),
        verify=False,
    )

    print(resp.status_code)
    print(resp.text)

    device_db = http_session.get(
        device_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps({}),
        verify=False,
    ).json()

    device_db["devices"].extend(device_list)

    print(json.dumps(device_db, indent=1))

    resp = http_session.post(
        device_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(device_db),
        verify=False,
    )

    print(resp)

    annotation_type_db = http_session.get(
        annotation_type_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(annotation_type),
        verify=False,
    ).json()

    annotation_type_db.update(annotation_type)

    resp = http_session.put(
        annotation_type_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(annotation_type_db),
        verify=False,
    )
    print(resp)

    annotation_servicename_db = http_session.get(
        annotation_servicename_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(annotation_type),
        verify=False,
    ).json()

    annotation_servicename_db.update(annotation_servicename)

    resp = http_session.put(
        annotation_servicename_url,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(annotation_servicename_db),
        verify=False,
    )
    print(resp)

