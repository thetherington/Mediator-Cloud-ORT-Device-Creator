import copy
import json
import uuid
from threading import Thread
from xml.dom import minidom

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class DeviceORTCreator:
    def __init__(self, **kwargs):

        self.proto = "https"
        self.address = "127.0.0.1"
        self.mediator_lookup = None

        self.username = "admin"
        self.password = "admin"

        self.device_route = "api/-/settings/device"
        self.logon_route = "api/v1/login"
        self.logout_route = "api/v1/logout"
        self.annotation_route = "api/-/model/catalog/annotation/ort-host-to-channelname"

        self.headers = {"Content-Type": "application/json;charset=UTF-8"}

        self.device_template = {
            "identification": {
                "uid": None,
                "alias": None,
                "matchables": [],
                "restrictable-ips": [""],
                "control-ips": [],
            },
            "grouping": {"tags": ["SDVN", "ORT"]},
        }

        self.system_name = None

        for key, value in kwargs.items():

            # mediator lookup has been enabled
            if key == "mediator":

                self.mediator_lookup = MediatorServiceCollector(**value)
                self.mediator_lookup.collect()

            # simple attributes are set as-is
            elif value:
                setattr(self, key, value)

            # single system set
            if key == "system_name":
                self.device_template["grouping"]["tags"].append(self.system_name)

    def process(self):

        with requests.Session() as http_session:

            # check that the logon process worked
            if self.logon(http_session):

                # grab the ort host to channel name annotations and
                # check that it's a valid dictionary
                annotations = self.fetch_annotation(http_session)

                if isinstance(annotations, dict):

                    changes = 0

                    # fetch the existing insite devices and reference in the device object
                    device_data = self.fetch_devices(http_session)
                    devices = device_data["devices"]

                    # iterate through all ort host-to-name annotations
                    for host, alias in annotations.items():

                        # iterate through each device in the devices list and check if
                        # annotated alias matches a device alias. if no breaking happens
                        # then the else block runs to create a new device.
                        for device in devices:

                            if alias == device["identification"]["alias"]:

                                # if mediator lookup is enabled, then use the tags in the device
                                # to match a system name in the mediator lookup class
                                if self.mediator_lookup:

                                    tags = self.mediator_lookup.return_systems(host)

                                    # empty tag list means mediator lookup catalog creation failed
                                    # or mediator is no longer keeping the ort annotions updated in insite
                                    # break out - ignore this annotation
                                    if not tags:
                                        break

                                    # if all the tags from the system name lookup matches with devices, then
                                    # check if a matchables update is needed. otherwise, the devices iteration continues,
                                    # and then a new device will be made for the new tag. (multiple systems with same ort names)
                                    # breaking causes the for else to cancel
                                    if all(tag in device["grouping"]["tags"] for tag in tags):

                                        if host not in device["identification"]["matchables"]:

                                            device["identification"]["matchables"].append(host)
                                            device["identification"]["control-ips"].append(host)

                                            changes += 1

                                        # everthing matches - no changes
                                        break

                                # single system so just update the matchables with there is a new hostname
                                # breaking causes the for else to cancel.
                                else:

                                    if host not in device["identification"]["matchables"]:

                                        device["identification"]["matchables"].append(host)
                                        device["identification"]["control-ips"].append(host)

                                        changes += 1

                                    # everthing matches - no changes
                                    break

                        # device iteration completes (no breaking)
                        # it's determined here that there should be a new device added to the devices list
                        else:

                            new_device = copy.deepcopy(self.device_template)

                            new_device["identification"]["uid"] = str(uuid.uuid4())
                            new_device["identification"]["alias"] = alias
                            new_device["identification"]["matchables"].append(host)
                            new_device["identification"]["control-ips"].append(host)

                            if self.mediator_lookup:
                                new_device["grouping"]["tags"].extend(
                                    self.mediator_lookup.return_systems(host)
                                )

                            devices.append(new_device)

                            changes += 1

                    # supress pushing new devices when there hasn't been any changes
                    # otherwise, post everything back
                    if changes > 0:
                        print(json.dumps(device_data, indent=1))
                        self.push_devices(device_data, http_session)

                    print(changes)

                self.logout()

    def fetch_annotation(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.annotation_route)

            resp = http_session.get(url, headers=self.headers, verify=False)

            if resp.status_code == 200:

                return json.loads(resp.text)

        except Exception as e:
            print(e)

        return None

    def logon(self, http_session=requests):

        try:

            logon_params = {"username": self.username, "password": self.password}
            url = "{}://{}/{}".format(self.proto, self.address, self.logon_route)

            resp = http_session.post(
                url, headers=self.headers, data=json.dumps(logon_params), verify=False,
            )

            if "ok" in resp.text:
                return resp.status_code

        except Exception as e:
            print(e)

        return None

    def fetch_devices(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.device_route)

            resp = http_session.get(url, headers=self.headers, verify=False)

            if resp.status_code == 200:
                return json.loads(resp.text)

        except Exception as e:
            print(e)

        return None

    def push_devices(self, device_data, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.device_route)

            resp = http_session.post(
                url, headers=self.headers, data=json.dumps(device_data), verify=False
            )

            if resp.status_code == 200:
                return json.loads(resp.text)

        except Exception as e:
            print(e)

        return None

    def logout(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.logout_route)

            resp = http_session.post(url, headers=self.headers, verify=False,)

            return resp.status_code

        except Exception as e:
            print(e)


class MediatorServiceCollector:
    def __init__(self, **kwargs):

        # self.hosts is a list of tuples [(IP:System Name)]
        self.hosts = []
        self.port = "8080"
        self.proto = "http"
        self.route = "info/scripts/CGItoXML.exe/servicerequest"
        self.sub = None
        self.collection = {}

        self.request_services_params = {
            "uniqueid": 0,
            "command": "getservices",
            "noxsl": None,
        }
        self.headers = {"Accept": "application/xml"}

        for key, value in kwargs.items():

            if value:
                setattr(self, key, value)

    def return_systems(self, host):

        return [system for system, hosts in self.collection.items() if host in hosts]

    def process(self, host, collection):
        def get_element(node, name):

            try:
                return node.getElementsByTagName(name)[0].firstChild.data

            except Exception:
                return None

        address = host[0]
        collection.update({host[1]: []})
        system_list = collection[host[1]]

        if self.sub:

            with open("_files\\" + host[1] + ".xml", "r") as f:
                content = [x for x in f.readlines()]

            doc = minidom.parseString("".join(content))

        else:

            try:

                url = "http://{}:{}/{}".format(address, self.port, self.route)

                resp = requests.get(
                    url, params=self.request_services_params, headers=self.headers, timeout=10.0,
                )

                doc = minidom.parseString(str(resp.text))

            except Exception as e:
                print(e)
                return None

        system_list.extend(
            [
                get_element(service, "HostName")
                for service in doc.getElementsByTagName("ServiceReg")
                if get_element(service, "Name") == "OvertureRT Driver"
            ]
        )

    def collect(self):

        # simultanously collect and merge all the system ORT devices together into a single collection
        threads = [
            Thread(target=self.process, args=(host, self.collection,)) for host in self.hosts
        ]

        for x in threads:
            x.start()

        for y in threads:
            y.join()

        print(self.collection)


def main():

    params = {
        "address": "172.16.112.14",
        # "system_name": "US_TX1_Production"
        "mediator": {
            "hosts": [
                ("10.127.3.56", "MAM_Production"),
                ("10.127.17.57", "US_TX1_Production"),
                ("10.127.130.177", "EU_TX1_Production"),
            ],
            "sub": True,
        },
    }

    ort_creator = DeviceORTCreator(**params)

    ort_creator.process()


if __name__ == "__main__":
    main()
