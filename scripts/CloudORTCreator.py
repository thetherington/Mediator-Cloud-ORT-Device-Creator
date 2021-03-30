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

        for key, value in kwargs.items():

            if value:
                setattr(self, key, value)

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

    params = {"address": "172.16.112.14"}

    ort_creator = DeviceORTCreator(**params)

    print(ort_creator.fetch_annotation())

    with requests.Session() as http_session:

        if ort_creator.logon(http_session):

            print(ort_creator.fetch_devices(http_session))
            print(ort_creator.logout(http_session))


if __name__ == "__main__":
    main()
