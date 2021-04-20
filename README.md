# Mediator Cloud ORT Device Creator

The purpose of this script module is to discover and create ORT devices in the inSITE Operations Panel from a dynamic cloud instance.  This script uses the __ORT - Host to Channel Name__ annotations which is pushed by a mediator system.  The script analyzes the ORT annotations and can produce either a) generate a device, b) modify a device, or c) delete a device from the operations panel.  This script aids in the ability to detect if an ORT cloud instance has been rebuilt because of a failure or auto scaling event. This script can also detect channel name changes for an ORT instance and update the inSITE operations panel, accordingly

Below are the module distinct abilities and features that it provides:

1. Adds, Modifies, and Removes ORT cloud instances for the operations panel.
2. Uses Mediator Infomation Center as a lookup base.
3. Supports multiple Mediator system with auto system tagging.
4. Supports ORT devices with the same channel name across multiple Mediator systems.
5. Maintains the General annotation lookup tables for Device Name, Device Type, and Service Name.
6. Prunes deprecated ORT channel annotations.
7. Generates remote syslog to a local logging server.

## Minimum Requirements:

- inSITE Version 10.3 and service pack 6
- Python3.7 (_already installed on inSITE machine_)
- Python3 Requests library (_already installed on inSITE machine_)

## Installation:

```
crontab -e
```

```
script="/home/insite/CloudORTCreator.py"
args="-syslog -insite 10.127.14.7"

*/5 * * * * python $script $args update
2 * * * * python $script $args annotations
7 12 * * * python $script $args devices
```
## Usage:

```
python CloudORTCreator.py -h
```

```
usage: CloudORTCreator.py [-h] [-insite <ip>] [-system name]
                          [-types Core Compute [Core Compute ...]]
                          [-info-center <IP>::<System_Name> [<IP>::<System_Name> ...]]
                          [-sub] [-syslog]
                          {update,annotations,devices} ...

inSITE Cloud ORT Creator / Maintainer

positional arguments:
  {update,annotations,devices}
    update              Discovery new and Update ORT devices
    annotations         Scan / Cleanup Mediator Channel ORT Annotations
    devices             Scan / Cleanup inSITE ORT Devices

optional arguments:
  -h, --help            show this help message and exit
  -insite <ip>, --insite-host <ip>
                        inSITE Host IP Address (default 127.0.0.1)
  -system name, --system-name name
                        Static system name to be used in tags
  -types Core Compute [Core Compute ...], --sync-device-types Core Compute [Core Compute ...]
                        Custom list of device types to sync
  -info-center <IP>::<System_Name> [<IP>::<System_Name> ...], --info-center-systems <IP>::<System_Name> [<IP>::<System_Name> ...]
                        List of Mediator info centers and associate system
                        names
  -sub, --mediator-sub  Substitute a local Mediator Service XML
  -syslog, --remote-syslog
                        Remote Syslog
```

