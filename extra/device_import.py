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

    # x = new list of devices
    # y = fetched db

    y_pops = []
    x_pops = []

    for index_y, y in enumerate(y_db["devices"]):

        for index_x, x in enumerate(x_list):

            if x["identification"]["alias"] == y["identification"]["alias"]:

                # if this tests true, then the newly created one matches exactly as the one in insite
                if set(x["identification"]["matchables"]) == set(
                    y["identification"]["matchables"]
                ) and set(x["grouping"]["tags"]) == set(y["grouping"]["tags"]):

                    x_pops.append(index_x)
                    x_list.pop(index_x)
                    break

                # if this tests true, then the hostname or ip has changed in the csv file. store the index
                # to have the fetched device to be removed later from the list
                elif set(x["identification"]["matchables"]) != set(
                    y["identification"]["matchables"]
                ) and set(x["grouping"]["tags"]) == set(y["grouping"]["tags"]):

                    y_pops.append(index_y)
                    break

                # device aliases match, and matchables are matching in the csv and fetched devices,
                # however the tags are different. possible the tag was wrong or device became something else.
                elif set(x["identification"]["matchables"]) == set(
                    y["identification"]["matchables"]
                ) and set(x["grouping"]["tags"]) != set(y["grouping"]["tags"]):

                    y_pops.append(index_y)
                    break

                # matchables are different and tags are different. this is a device with the
                # same name/type but in another system.
                else:
                    continue

    # pop out all the indexes found from the fetched device list
    _ = [y_db["devices"].pop(pop) for pop in y_pops]

    return len(x_pops), len(y_pops)


with requests.Session() as http_session:

    post(http_session, LOGON_URL, {"username": "admin", "password": "admin"})

    device_db = get(http_session, DEVICE_URL)
    print("Fetched %s Devices" % (len(device_db["devices"])))

    count_x, count_y = remove_duplicate_devices(device_list, device_db)
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
