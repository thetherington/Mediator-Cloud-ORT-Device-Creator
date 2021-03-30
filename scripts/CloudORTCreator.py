import copy
import json
import uuid

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class DeviceORTCreator:
    def __init__(self, **kwargs):

        self.proto = "https"
        self.address = "127.0.0.1"
        self.consul = "8501"

        self.username = "admin"
        self.password = "admin"

        self.device_route = "api/-/settings/device"
        self.logon_route = "api/v1/login"
        self.logout_route = "api/v1/logout"
        self.annotation_route = "evertz/insite/common/node/ALL/applications/ALL-SYSTEM/catalog/annotation/catalog/ort-host-to-channelname"

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

            if value:
                setattr(self, key, value)

            if key == "system_name":
                self.device_template["grouping"]["tags"].append(self.system_name)

    def process(self):

        annotations = self.fetch_annotation()

        if isinstance(annotations, dict):

            with requests.Session() as http_session:

                if self.logon(http_session):

                    changes = 0

                    device_data = self.fetch_devices(http_session)
                    devices = device_data["devices"]

                    for host, alias in annotations.items():

                        for device in devices:

                            if alias == device["identification"]["alias"]:

                                if host not in device["identification"]["matchables"]:

                                    device["identification"]["matchables"].append(host)
                                    device["identification"]["control-ips"].append(host)

                                break

                        else:

                            new_device = copy.deepcopy(self.device_template)

                            new_device["identification"]["uid"] = str(uuid.uuid4())
                            new_device["identification"]["alias"] = alias
                            new_device["identification"]["matchables"].append(host)
                            new_device["identification"]["control-ips"].append(host)

                            devices.append(new_device)

                            changes += 1

                    # print(json.dumps(device_data, indent=1))
                    self.push_devices(device_data, http_session)

                    print(changes)

                    self.logout()

    def fetch_annotation(self):

        try:

            url = "{}://{}:{}/v1/kv/{}".format(
                self.proto, self.address, self.consul, self.annotation_route
            )

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            params = {"raw": ""}

            with requests.Session() as http_session:

                resp = http_session.get(url, headers=headers, params=params, verify=False)

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


def main():

    params = {"address": "172.16.112.14", "system_name": "US_TX1_Production"}

    ort_creator = DeviceORTCreator(**params)

    print(ort_creator.fetch_annotation())

    ort_creator.process()


if __name__ == "__main__":
    main()
