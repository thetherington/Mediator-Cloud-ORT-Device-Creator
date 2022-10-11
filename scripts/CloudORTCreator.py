import argparse
import copy
import json
import logging
import logging.handlers
import re
import socket
import sys
import uuid
from threading import Thread
from xml.dom import minidom

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class DeviceORTCreator:
    def __init__(self, logger=logging.getLogger(), **kwargs):

        self.logger = logger

        self.proto = "https"
        self.address = "127.0.0.1"
        self.mediator_lookup = None
        self.sync_service_names = None
        self.sync_device_types = None

        self.username = "admin"
        self.password = "admin"

        self.device_route = "api/-/settings/device-identity"
        self.logon_route = "api/v1/login"
        self.logout_route = "api/v1/logout"
        self.annotation_route = "api/-/model/catalog/annotation/ort-host-to-channelname"
        self.service_name_route = (
            "api/-/model/catalog/annotation/general-host-to-servicename"
        )
        self.system_name_route = (
            "api/-/model/catalog/annotation/general-host-to-systemname"
        )
        self.device_type_route = (
            "api/-/model/catalog/annotation/general-host-to-devicetype"
        )
        self.device_name_route = (
            "api/-/model/catalog/annotation/general-host-to-devicename"
        )

        self.ort_host_channel = "api/-/model/catalog/annotation/ort-host-to-channelname"
        self.ort_host_zone = (
            "api/-/model/catalog/annotation/ort-orthost-to-availabilityzone"
        )
        self.ort_host_instance = (
            "api/-/model/catalog/annotation/ort-orthost-to-instanceid"
        )
        self.ort_stream_channel = (
            "api/-/model/catalog/annotation/ort-streamaddress-to-channelname"
        )
        self.ort_channel_host = (
            "api/-/model/catalog/annotation/ort-channelname-to-orthost"
        )

        self.aws_host_zone = "api/-/model/catalog/annotation/aws-host-to-availabilityzone"
        self.aws_host_instance = "api/-/model/catalog/annotation/aws-host-to-instanceid"

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

        self.host_lookup_query = {
            "query": {"range": {"@timestamp": {"from": "now-10d", "to": "now"}}},
            "aggs": {
                "hosts": {
                    "terms": {"field": "agent.hostname", "size": 1000},
                    "aggs": {
                        "annotations": {
                            "terms": {
                                "field": "annotation.general.device_name",
                                "size": 100,
                            }
                        }
                    },
                },
                "systems": {
                    "terms": {"field": "annotation.general.service_name", "size": 10},
                    "aggs": {
                        "annotations": {
                            "terms": {
                                "field": "annotation.general.device_name",
                                "size": 1000,
                            }
                        }
                    },
                },
            },
            "size": 0,
        }
        self.query_index = "log-systeminfo-*"

        self.system_name = None

        for key, value in kwargs.items():

            # mediator lookup has been enabled
            if key == "mediator":

                self.mediator_lookup = MediatorServiceCollector(self.logger, **value)
                self.mediator_lookup.collect()
                self.sync_service_names = True

            # simple attributes are set as-is
            elif value:
                setattr(self, key, value)

            # single system set
            if key == "system_name" and value:
                self.device_template["grouping"]["tags"].append(self.system_name)
                # self.sync_service_names = True

        self.hostname_pattern = re.compile(
            r"ip-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        )

    def scan_ort_devices(self):

        with requests.Session() as http_session:

            if self.logon(http_session):

                # get a flat list of terms found in the systeminfo index
                # get a list of objects that are a hostname with multiple channel names
                (
                    host_bucket_list,
                    host_duplicates,
                    system_names,
                ) = self.query_for_annotations(self.host_lookup_query, self.query_index)

                device_data = self.fetch_devices(http_session)
                annotations = self.fetch_annotation(http_session)

                if isinstance(device_data, dict):

                    self.logger.debug(
                        "Number of devices fetched %s", len(device_data["devices"])
                    )

                    changes = 0

                    device_delete_list = []

                    # #  perform sanitization for expired matchables in devices
                    # 1) iterate through each device if it has ORT in tags
                    # 2) iterate through all the aws ip hostnames with regex expression
                    # 3) check if aws ip hostname not in database query results and not in current ort annotaitons
                    # 4) then remove aws ip hostname and ip address from device lists
                    # 5) if the device has empty lists, then add the device to the remove list
                    for device in device_data["devices"]:

                        if "ORT" in device["grouping"]["tags"]:

                            # regex pattern match for ip-xxx-xxx-xxx-xxx
                            for ip in self.hostname_pattern.finditer(
                                str(device["identification"]["matchables"])
                            ):

                                # group 0 is the full match of the ip-xxx-xxx-xxx-xxx pattern
                                # host_bucket_list contains flat list of host name terms in the systeminfo index
                                # if the aws ip hostname is not in the database, then the hostname is expired.
                                if (
                                    ip.group(0) not in host_bucket_list
                                    and ip.group(0) not in annotations.keys()
                                ):

                                    self.logger.info(
                                        "%s [%s] - Removing expired host: %s",
                                        device["identification"]["alias"],
                                        max(device["grouping"]["tags"], key=len),
                                        ip.group(0),
                                    )

                                    device["identification"]["matchables"].remove(
                                        ip.group(0)
                                    )
                                    device["identification"]["control-ips"].remove(
                                        ip.group(0)
                                    )

                                    # create a regular ip by joining all the groups together
                                    # remove the regular ip from the device lists
                                    device["identification"]["matchables"].remove(
                                        ".".join(ip.groups())
                                    )
                                    device["identification"]["control-ips"].remove(
                                        ".".join(ip.groups())
                                    )

                                    changes += 1

                            # if this happens, then all the matchables were removed because of no data
                            # possible this device is abandoned in the system since mediator doesn't keep
                            # track of it as a channel or there's no overture rt driver
                            if len(device["identification"]["matchables"]) < 1:

                                device_delete_list.append(device)

                                self.logger.error(
                                    "ORT: %s Has no valid matchables and is going to be removed -- %s",
                                    device["identification"]["alias"],
                                    max(device["grouping"]["tags"], key=len),
                                )

                                changes += 1

                            # if the matchables only has one value, then there's a good chance that just the
                            # system name is in the matchables. need to check if the device name is not in the
                            # system name group. if not, then consider it dormant.
                            elif (
                                len(device["identification"]["matchables"]) == 1
                                and device["identification"]["matchables"][-1]
                                in system_names.keys()
                            ):

                                if device["identification"][
                                    "alias"
                                ] not in system_names.get(
                                    device["identification"]["matchables"][-1], []
                                ):

                                    device_delete_list.append(device)

                                    self.logger.error(
                                        "ORT: %s Has been dormant and now has no data -- %s",
                                        device["identification"]["alias"],
                                        max(device["grouping"]["tags"], key=len),
                                    )

                                    changes += 1

                    # scan and purge duplicates which two devices that share a matchable
                    # this may likely happen because of a channel rename. but in a more
                    # bizzare scenario that the ort shutdown, then a new channel came up with the same ip
                    for key, value in host_duplicates.items():

                        # returns none if detected dup key is not in active ort annotations
                        active_channel = annotations.get(key, None)

                        if active_channel:

                            # get the difference from the value list and the active ort name for the host
                            inactive_channels = list(set(value) - set([active_channel]))

                            for device in device_data["devices"]:

                                # if a device is found then remake the matchables with the device
                                # system name
                                if (
                                    "ORT" in device["grouping"]["tags"]
                                    and device["identification"]["alias"]
                                    in inactive_channels
                                    and key in device["identification"]["matchables"]
                                ):

                                    device["identification"]["matchables"] = [
                                        max(device["grouping"]["tags"], key=len)
                                    ]
                                    device["identification"]["control-ips"] = [
                                        max(device["grouping"]["tags"], key=len)
                                    ]

                                    changes += 1

                                    self.logger.warning(
                                        "ORT: %s is now inactive, now replaced by %s -- %s",
                                        device["identification"]["alias"],
                                        active_channel,
                                        max(device["grouping"]["tags"], key=len),
                                    )

                        # abandon channel names that are no longer tracked by mediator
                        # pretty rare for this to happen unless there's rapid testing with channel replacements
                        # in the future it would be better to keep atleast one based on last data received.
                        else:

                            for device in device_data["devices"]:

                                if (
                                    "ORT" in device["grouping"]["tags"]
                                    and device["identification"]["alias"] in value
                                    and key in device["identification"]["matchables"]
                                ):

                                    device["identification"]["matchables"] = [
                                        max(device["grouping"]["tags"], key=len)
                                    ]
                                    device["identification"]["control-ips"] = [
                                        max(device["grouping"]["tags"], key=len)
                                    ]

                                    changes += 1

                                    self.logger.warning(
                                        "ORT: %s is now inactive because duplicate, without replacement-- %s",
                                        device["identification"]["alias"],
                                        max(device["grouping"]["tags"], key=len),
                                    )

                    # purge devices that have been added to the delete list.
                    for device in device_delete_list:
                        device_data["devices"].remove(device)

                    if changes > 0:

                        self.logger.info(
                            "Pushing %s Devices", len(device_data["devices"])
                        )

                        rtrn_devices = self.push_devices(device_data, http_session)
                        self.logger.debug(
                            "Returned %s Devices", len(rtrn_devices["devices"])
                        )

                        # update the General - Host to System Names with the device_data
                        # note: the device location is found by getting the longest string in the tag list
                        self.update_system_names(device_data, http_session, rebuild=True)

                        # update the General - Host to Device Types with the device_data
                        # note: this is needed until the bug if fixed to use a sorted tags list in inSITE
                        # otherwise, device types will have the wrong tag.
                        self.update_device_types(device_data, http_session, rebuild=True)

                        # rebuild the device_names so there's no unused key/value pairs.
                        self.update_device_names(device_data, http_session, rebuild=True)

                        self.logger.debug(json.dumps(device_data, indent=1))

                    self.logger.info("Device Changes Recorded: %s", changes)

                self.logout(http_session)

    def scan_ort_annotations(self):

        with requests.Session() as http_session:

            # check that the logon process worked
            if self.logon(http_session):

                host_channels = self.get_annotation(self.ort_host_channel, http_session)

                # check if the annotations fetching worked first
                if host_channels:

                    purge_list = {}

                    # iterate through the annotations and check each item is in the
                    # mediator catalog. if not, then add to purge list
                    for host, channel_name in host_channels.items():

                        if self.mediator_lookup:
                            if host not in self.mediator_lookup.return_hosts():
                                purge_list.update({host: channel_name})

                    if len(purge_list.keys()) > 0:

                        self.logger.info(
                            "Purging %s hostnames annotations", len(purge_list.keys())
                        )
                        self.logger.debug(json.dumps(purge_list))

                        # scan through each annotation, and pop out keys that are in the
                        # purge list keys. then put back the annotations db.
                        for annotation in [
                            self.ort_host_channel,
                            self.ort_host_zone,
                            self.ort_host_instance,
                            self.aws_host_instance,
                            self.aws_host_zone,
                        ]:

                            annotation_data = self.get_annotation(
                                annotation, http_session
                            )
                            count = len(annotation_data.keys())

                            for key, _ in purge_list.items():
                                annotation_data.pop(key, None)

                            self.logger.info(
                                "Pushing %s - Old: %s, New: %s",
                                annotation.split("/")[-1],
                                count,
                                len(annotation_data.keys()),
                            )

                            self.push_annotation(
                                annotation, annotation_data, http_session
                            )

                    else:
                        self.logger.info("Nothing to purge")

                else:
                    self.logger.info("Channel annotations is empty")

                self.logout(http_session)

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
                    # check that it's a valid dictionary
                    device_data = self.fetch_devices(http_session)

                    if isinstance(device_data, dict):

                        devices = device_data["devices"]
                        self.logger.info("Number of devices fetched %s", len(devices))

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

                                            self.logger.error(
                                                "Missing ORT from Mediator: %s", host
                                            )
                                            break

                                        # if all the tags from the system name lookup matches with devices, then
                                        # check if a matchables update is needed. otherwise, the devices iteration continues,
                                        # and then a new device will be made for the new tag. (multiple systems with same ort names)
                                        # breaking causes the for else to cancel
                                        if all(
                                            tag in device["grouping"]["tags"]
                                            for tag in tags
                                        ):

                                            if (
                                                host
                                                not in device["identification"][
                                                    "matchables"
                                                ]
                                            ):

                                                device["identification"][
                                                    "matchables"
                                                ].append(host)
                                                device["identification"][
                                                    "control-ips"
                                                ].append(host)

                                                self.hostname_ip_convert(device)

                                                changes += 1

                                                self.logger.warning(
                                                    "ORT: %s Updated: %s -- %s",
                                                    alias,
                                                    host,
                                                    max(
                                                        device["grouping"]["tags"],
                                                        key=len,
                                                    ),
                                                )

                                            # everthing matches - no changes
                                            break

                                    # single system so just update the matchables with there is a new hostname
                                    # breaking causes the for else to cancel.
                                    else:

                                        if (
                                            host
                                            not in device["identification"]["matchables"]
                                        ):

                                            device["identification"]["matchables"].append(
                                                host
                                            )
                                            device["identification"][
                                                "control-ips"
                                            ].append(host)

                                            self.hostname_ip_convert(device)

                                            changes += 1

                                            self.logger.warning(
                                                "ORT: %s Updated: %s -- %s",
                                                alias,
                                                host,
                                                max(device["grouping"]["tags"], key=len),
                                            )

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

                                self.hostname_ip_convert(new_device)

                                devices.append(new_device)

                                self.logger.info(
                                    "New Device added: %s [%s] -- %s",
                                    alias,
                                    host,
                                    max(new_device["grouping"]["tags"], key=len),
                                )

                                changes += 1

                        # supress pushing new devices when there hasn't been any changes
                        # otherwise, post everything back
                        if changes > 0:

                            self.logger.info(
                                "Pushing %s Devices", len(device_data["devices"])
                            )

                            rtrn_devices = self.push_devices(device_data, http_session)

                            # update the General - Host to Service Names with the device_data
                            # note: the device location is found by getting the longest string in the tag list

                            # don't have to do this update anymore in v11 since updating a device updates annotation types now
                            # if self.sync_service_names:
                            #     self.update_service_names(device_data, http_session)

                            # update the General - Host to Device Types with the device_data
                            # note: this is needed until the bug if fixed to use a sorted tags list in inSITE
                            # otherwise, device types will have the wrong tag.

                            # don't have to do this update anymore in v11 since updating a device updates annotation types now
                            # if self.sync_device_types:
                            #     self.update_device_types(device_data, http_session)

                            self.logger.info(
                                "Returned %s Devices", len(rtrn_devices["devices"])
                            )
                            self.logger.debug(json.dumps(device_data, indent=1))

                        self.logger.info("Changes Recorded: %s", changes)

                self.logout()

    def fetch_annotation(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.annotation_route)

            resp = http_session.get(url, headers=self.headers, verify=False)

            if resp.status_code == 200:

                return json.loads(resp.text)

        except Exception as e:
            self.logger.critical(e)

        return None

    def logon(self, http_session=requests):

        try:

            self.logger.debug(
                "Logging in as user: %s, pass: %s", self.username, self.password
            )

            logon_params = {"username": self.username, "password": self.password}
            url = "{}://{}/{}".format(self.proto, self.address, self.logon_route)

            resp = http_session.post(
                url,
                headers=self.headers,
                data=json.dumps(logon_params),
                verify=False,
            )

            if "ok" in resp.text:
                return resp.status_code

        except Exception as e:
            self.logger.critical(e)

        self.logger.warning("Logon failed")

        return None

    def fetch_devices(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.device_route)

            resp = http_session.get(url, headers=self.headers, verify=False)

            if resp.status_code == 200:
                return json.loads(resp.text)

        except Exception as e:
            self.logger.critical(e)

        self.logger.warning(
            "Failed to collect devices, reason: %s, status code: %s",
            resp.text,
            resp.status_code,
        )
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
            self.logger.critical(e)

        self.logger.warning(
            "Failed to push devices, reason: %s, status code: %s",
            resp.text,
            resp.status_code,
        )
        return None

    def logout(self, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, self.logout_route)

            resp = http_session.post(
                url,
                headers=self.headers,
                verify=False,
            )

            return resp.status_code

        except Exception as e:
            self.logger.warning(e)

    def update_device_names(self, device_data, http_session=requests, rebuild=False):

        try:

            annotations = {}

            url = "{}://{}/{}".format(self.proto, self.address, self.device_name_route)

            device_name_db = http_session.get(
                url, headers=self.headers, verify=False
            ).json()

            for device in device_data["devices"]:

                for host_name in device["identification"]["matchables"]:

                    annotations.update({host_name: device["identification"]["alias"]})

            if rebuild:
                device_name_db = annotations

            else:
                device_name_db.update(annotations)

            resp = http_session.put(
                url, data=json.dumps(device_name_db), headers=self.headers, verify=False
            )

            self.logger.info(
                "Updated General - Host to Device Names with: %s keys",
                len(annotations.keys()),
            )

            return resp.status_code

        except Exception as e:
            self.logger.critical(e)
            return None

    def update_service_names(self, device_data, http_session=requests, rebuild=False):

        try:

            annotations = {}

            url = "{}://{}/{}".format(self.proto, self.address, self.service_name_route)

            service_name_db = http_session.get(
                url, headers=self.headers, verify=False
            ).json()

            for device in device_data["devices"]:

                for host_name in device["identification"]["matchables"]:

                    annotations.update(
                        {host_name: max(device["grouping"]["tags"], key=len)}
                    )

            if rebuild:
                service_name_db = annotations

            else:
                service_name_db.update(annotations)

            resp = http_session.put(
                url, data=json.dumps(service_name_db), headers=self.headers, verify=False
            )

            self.logger.info(
                "Updated General - Host to Service Names with: %s keys",
                len(annotations.keys()),
            )

            return resp.status_code
        except Exception as e:
            self.logger.critical(e)
            return None

    def update_system_names(self, device_data, http_session=requests, rebuild=False):

        try:

            annotations = {}

            url = "{}://{}/{}".format(self.proto, self.address, self.system_name_route)

            system_name_db = http_session.get(
                url, headers=self.headers, verify=False
            ).json()

            for device in device_data["devices"]:

                for host_name in device["identification"]["matchables"]:

                    annotations.update(
                        {host_name: max(device["grouping"]["tags"], key=len)}
                    )

            if rebuild:
                system_name_db = annotations

            else:
                system_name_db.update(annotations)

            resp = http_session.put(
                url, data=json.dumps(system_name_db), headers=self.headers, verify=False
            )

            self.logger.info(
                "Updated General - Host to System Names with: %s keys",
                len(annotations.keys()),
            )

            return resp.status_code
        except Exception as e:
            self.logger.critical(e)
            return None

    def update_device_types(self, device_data, http_session=requests, rebuild=False):

        try:

            annotations = {}

            url = "{}://{}/{}".format(self.proto, self.address, self.device_type_route)

            device_type_db = http_session.get(
                url, headers=self.headers, verify=False
            ).json()

            for device in device_data["devices"]:

                # two lists converted to sets and "&" together will produce a set of anything that matches
                # this code was to match known types with an item from the tags list
                # this was because the tags were often re-arranged for some reason making the type not easy to find

                # tags = set(device["grouping"]["tags"]) & set(
                #     ["Core", "Compute", "inSITE", "CloudBridge", "ORT"]
                # )

                # i've found that in inSITE v11 that the tags list is always ordered the same
                # and the type is the second item in the tags list
                if len(device["grouping"]["tags"]) >= 2:
                    tags = [device["grouping"]["tags"][1]]
                else:
                    # no type if tags doesn't contain atleast 2 items.
                    tags = []

                _ = [
                    annotations.update({host_name: tag})
                    for tag in tags
                    for host_name in device["identification"]["matchables"]
                ]

            if rebuild:
                device_type_db = annotations

            else:
                device_type_db.update(annotations)

            resp = http_session.put(
                url, data=json.dumps(device_type_db), headers=self.headers, verify=False
            )

            self.logger.info(
                "Updated General - Host to Device Type with: %s keys",
                len(annotations.keys()),
            )

            return resp.status_code

        except Exception as e:
            self.logger.critical(e)
            return None

    def get_annotation(self, annotation, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, annotation)

            resp = http_session.get(url, headers=self.headers, verify=False).json()

            self.logger.debug(
                "Fetched Annotation Group: %s - Count: %s", annotation, len(resp.keys())
            )

            return resp

        except Exception as e:

            self.logger.critical(
                "(get_annotation) -- Annotation Group: %s - %s", annotation, e
            )
            return None

    def push_annotation(self, annotation, data, http_session=requests):

        try:

            url = "{}://{}/{}".format(self.proto, self.address, annotation)

            resp = http_session.put(
                url, data=json.dumps(data), headers=self.headers, verify=False
            )

            self.logger.debug(
                "Pushed Annotation Group: %s - Status: %s", annotation, resp.status_code
            )

            return resp.status_code

        except Exception as e:
            self.logger.critical(
                "(push_annotation) -- Annotation Group: %s - %s", annotation, e
            )
            return None

    def query_for_annotations(self, query, index, http_session=requests):

        hostname_list = []
        hostname_multi_channel = {}
        system_name_groups = {}

        try:

            url = "{}://{}:9200/{}/_search".format("http", self.address, index)
            params = {"ignore_unavailable": "true"}

            resp = http_session.get(
                url,
                data=json.dumps(query),
                params=params,
                headers=self.headers,
                verify=False,
            ).json()

            self.logger.debug(
                "Fetched (%s) - Took: %s, Timeout: %s, Hits: %s, Buckets: %s",
                url,
                resp["took"],
                resp["timed_out"],
                resp["hits"]["total"],
                len(resp["aggregations"]["hosts"]["buckets"]),
            )

            for hostname_term in resp["aggregations"]["hosts"]["buckets"]:

                hostname_list.append(hostname_term["key"])

                ort_names = [
                    channel_term["key"]
                    for channel_term in hostname_term["annotations"]["buckets"]
                ]

                if len(ort_names) > 1:
                    hostname_multi_channel.update({hostname_term["key"]: ort_names})

            for system in resp["aggregations"]["systems"]["buckets"]:

                system_name_groups.update(
                    {
                        system["key"]: [
                            device_name["key"]
                            for device_name in system["annotations"]["buckets"]
                        ]
                    }
                )

        except Exception as e:
            self.logger.critical("(query_for_annotations) -- URL: %s - %s", url, e)

        return hostname_list, hostname_multi_channel, system_name_groups

    def hostname_ip_convert(self, device):

        for key in ["matchables", "control-ips"]:

            for hostname in device["identification"][key]:

                device["identification"][key].extend(
                    [
                        ".".join(x.groups())
                        for x in self.hostname_pattern.finditer(hostname)
                        if ".".join(x.groups()) not in device["identification"][key]
                    ]
                )


class MediatorServiceCollector:
    def __init__(self, logger=logging.getLogger(), **kwargs):

        # self.hosts is a list of tuples [(IP:System Name)]
        self.hosts = []
        self.port = "8080"
        self.proto = "http"
        self.route = "info/scripts/CGItoXML.exe/servicerequest"
        self.sub = None
        self.collection = {}

        self.logger = logger

        self.request_services_params = {
            "uniqueid": 0,
            "command": "getservices",
            "noxsl": None,
        }
        self.headers = {"Accept": "application/xml"}

        for key, value in kwargs.items():

            if value:
                setattr(self, key, value)

    def return_hosts(self):

        return [y for _, x in self.collection.items() for y in x]

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
                    url,
                    params=self.request_services_params,
                    headers=self.headers,
                    timeout=10.0,
                )

                doc = minidom.parseString(str(resp.text))

            except Exception as e:
                self.logger.critical(e)
                return None

        system_list.extend(
            [
                get_element(service, "HostName")
                for service in doc.getElementsByTagName("ServiceReg")
                if get_element(service, "Name") == "OvertureRT Driver"
            ]
        )

        self.logger.info("System: %s, Number of hosts: %s", host[1], len(system_list))

    def collect(self):

        # simultanously collect and merge all the system ORT devices together into a single collection
        threads = [
            Thread(
                target=self.process,
                args=(
                    host,
                    self.collection,
                ),
            )
            for host in self.hosts
        ]

        for x in threads:
            x.start()

        for y in threads:
            y.join()

        self.logger.debug(self.collection)


def main(data):

    parser = argparse.ArgumentParser(description="inSITE Cloud ORT Creator / Maintainer")

    sub = parser.add_subparsers(dest="update, annotations or devices")
    sub.required = True

    sub_update = sub.add_parser("update", help="Discovery new and Update ORT devices")
    sub_update.set_defaults(which="update")

    sub_annotations = sub.add_parser(
        "annotations", help="Scan / Cleanup Mediator Channel ORT Annotations"
    )
    sub_annotations.set_defaults(which="annotations")

    sub_devices = sub.add_parser("devices", help="Scan / Cleanup inSITE ORT Devices")
    sub_devices.set_defaults(which="devices")

    parser.add_argument(
        "-insite",
        "--insite-host",
        required=False,
        type=str,
        metavar="<ip>",
        default="127.0.0.1",
        help="inSITE Host IP Address (default 127.0.0.1)",
    )
    parser.add_argument(
        "-system",
        "--system-name",
        required=False,
        metavar="name",
        help="Static system name to be used in tags",
    )
    parser.add_argument(
        "-types",
        "--sync-device-types",
        required=False,
        metavar="Core Compute",
        nargs="+",
        default=["Core", "Compute", "inSITE", "CloudBridge", "ORT"],
        help="Custom list of device types to sync",
    )
    parser.add_argument(
        "-info-center",
        "--info-center-systems",
        required=False,
        metavar="<IP>::<System_Name>",
        nargs="+",
        help="List of Mediator info centers and associate system names",
    )
    parser.add_argument(
        "-sub",
        "--mediator-sub",
        required=False,
        action="store_true",
        help="Substitute a local Mediator Service XML",
    )
    parser.add_argument(
        "-syslog",
        "--remote-syslog",
        required=False,
        action="store_true",
        help="Remote Syslog",
    )

    args = parser.parse_args()
    # args = parser.parse_args(
    #     [
    #         "-insite",
    #         "172.16.112.40",
    #         "-insite",
    #         "172.16.112.40",
    #         "-system",
    #         "MAM",
    #         "devices",
    #     ]
    # )

    params = {
        "address": args.insite_host,
        # "sync_device_types": args.sync_device_types,
        "sync_device_types": None,
        "sync_service_names": None,
        "system_name": args.system_name,
        "mediator": {
            "hosts": [],
            "sub": args.mediator_sub,
        },
    }

    if args.info_center_systems:

        params["mediator"]["hosts"] = [
            tuple(x.split("::")) for x in args.info_center_systems if "::" in x
        ]

        if len(params["mediator"]["hosts"]) < 1:
            print("No valid mediator info center hosts")
            quit()

    elif data:
        params["mediator"]["hosts"].extend(data)

    else:
        params.pop("mediator", None)

    if args.remote_syslog:

        logger = logging.getLogger(socket.gethostname())
        handler = logging.handlers.SysLogHandler(
            address=(params["address"], 514), facility=19
        )
        formatter = logging.Formatter(
            "%(asctime)s %(name)s "
            + 'CloudORTCreator[%(process)d]: device_meta=({"lineno": "%(lineno)s", "function": "%(funcName)s", "message": "%(message)s"}) '
        )

    else:

        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s : %(levelname)s : %(name)s %(funcName)s:%(lineno)d : %(message)s"
        )

    logger.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    ort_creator = DeviceORTCreator(logger, **params)

    if args.which == "update":
        ort_creator.process()

    elif args.which == "annotations":
        ort_creator.scan_ort_annotations()

    elif args.which == "devices":
        ort_creator.scan_ort_devices()


if __name__ == "__main__":

    hosts = []

    # hosts = [
    #     ("10.127.3.56", "MAM_Production"),
    #     ("10.127.17.57", "US_TX1_Production"),
    #     ("10.127.130.177", "EU_TX1_Production"),
    # ]

    main(hosts)
