#!/usr/bin/python
import re
import json
import requests
import boto3
import collections
import sys
from pprint import pprint
from evertz.public import MediatorWSHTTPClient
from evertz.utils import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(SNIMissingWarning)

logger = logging.getLogger(__name__)
insitesession = requests.Session()

logger.info('Attempting to login to Mediator...')
runner_env = sys.argv[1].split('+')
host = runner_env[0]
skey = runner_env[1]
jobid = runner_env[2]
mediator = MediatorWSHTTPClient(host, skey)

try:
    jobProperties = mediator.job.get(
        jobid)['Job']['Description']['Properties']
except KeyError as e:
    logger.error('Unable to pull JobDescription > Properties. Expecting (' +
                 e.args[0] + ') but no such element found')
    sys.exit(1)

requiredProperties = {"insiteUsername": None, "insiteHosts": "StringList",
                      "insitePassword": None, "cloudbridgeMapping": "StringList"}
for requiredProperty, type in requiredProperties.iteritems():
    if requiredProperty not in jobProperties:
        logger.error('Required property (%s) of type (%s) missing' %
                     (requiredProperty, type))
        sys.exit(1)
    if type is not None and type != list(jobProperties[requiredProperty])[0]:
        logger.error('Required property (%s) is not of correct type. Expecting type (%s), got (%s)' % (
            requiredProperty, type, list(jobProperties[requiredProperty])[0]))
        sys.exit(1)

cloudbridgeMapping = {}
# Temporary/Messy solution as Key/Value maps of any type we're not working in x59 when this was implemented...
for mapping in jobProperties['cloudbridgeMapping']['StringList']['String']:
    if not re.match('"[^"]+" : "[^"]+"', mapping):
        logger.error(
            'cloudbridgeMapping (%s) does not match regex ("[^"]+" : "[^"]+")' % (mapping))
        sys.exit(1)
    mapping = mapping.encode("utf-8").split(':')
    ip = mapping[0].lstrip().rstrip()[1:-1]
    host = mapping[1].lstrip().rstrip()[1:-1]
    cloudbridgeMapping[ip] = host

insiteHostnames = jobProperties['insiteHosts']['StringList']['String']
insiteUsername = jobProperties['insiteUsername']
insitePassword = jobProperties['insitePassword']


def processData():
    # Get the Zone & DNS name from AWS
    logger.info('Pulling metadata from AWS... This make take a minute!')
    awsInstances = collections.defaultdict()
    for region in ['us-east-1', 'eu-west-1']:
        ec2 = boto3.resource('ec2', region_name=region)

        runningInstances = ec2.instances.filter(Filters=[{
            'Name': 'instance-state-name',
            'Values': ['running']}])

        for instance in runningInstances:
            awsInstances[instance.id] = {
                'AZ': instance.placement['AvailabilityZone'],
                'DNSName': instance.private_dns_name
            }
    logger.info('Pulled metatdata from AWS!')

    # Run the Mediator report
    try:
        logger.info('Running Mediator report insiteVistalinkData...')
        reportResults = mediator.generic_call('report', 'runReport', reportName='insiteVistalinkData', pageSize=10000, page=1)[
            'ReportResult']['ResultList']['PagedResults']['Results']
    except KeyError as e:
        logger.error('Mediator WSCall returned Invalid data. Expecting (' +
                     e.args[0] + ') but no such element found')
        sys.exit(1)
    except Exception as e:
        logger.error('Mediator WSCall threw an exception: ' + str(e))
        sys.exit(1)
    logger.info('Report ran sucesfully!')

    # Check the instance exists in AWS, add additional metadata and format it
    logger.info('Validating collected data...')
    results = collections.defaultdict()
    for rr in reportResults:
        if rr['InstanceID'] not in awsInstances:
            logger.warning('Instance ID (%s) assigned to (%s) not found in AWS - Removing...' %
                           (rr['InstanceID'], rr['ApparatusLocator']))
        elif rr['StreamAddress'].split(':')[0] not in cloudbridgeMapping:
            logger.info(str(cloudbridgeMapping))
            logger.warning('Instance ID (%s) assigned to (%s) has cloudbridge (%s) defined which does not exist in local mapping - Removing...' %
                           (rr['InstanceID'], rr['ApparatusLocator'], rr['StreamAddress'].split(':')[0]))
        else:
            results[rr['ApparatusLocator']] = {
                'InstanceID': rr['InstanceID'],
                'FormattedApparatusDescription': rr['ApparatusDescription'].upper().replace(' ', '_'),
                'StreamAddress': cloudbridgeMapping[rr['StreamAddress'].split(':')[0]] + ':' + rr['StreamAddress'].split(':')[1],
                'ApparatusHostName': rr['ApparatusHostName'],
                'AWSZone': awsInstances[rr['InstanceID']]['AZ'],
            }
    logger.info('Validated collected data! Building data structure...')

    if not results.values():
        logger.error(
            'No results returned from data validation. Check report data/cloudbridge mappings')
        sys.exit(1)

    # We know we have the required data moving forward, so we'll format it the correct way without additional checking
    # TODO: Make this better. It's json with duplicate keys in some places. Not sure how best to do that in Python?
    hostToAZ = '{'
    hostToInstanceID = '{'
    channelNameToHost = '{'
    hostToChannelName = '{'
    streamAddressToChannelName = '{'
    loopCount = 1
    for appar in results.values():
        if loopCount == len(results):
            terminator = '"}'
        else:
            terminator = '",'
        hostToAZ = hostToAZ + '"' + \
            appar['ApparatusHostName'] + '":"' + appar['AWSZone'] + terminator
        hostToInstanceID = hostToInstanceID + '"' + \
            appar['ApparatusHostName'] + '":"' + \
            appar['InstanceID'] + terminator
        channelNameToHost = channelNameToHost + '"' + \
            appar['FormattedApparatusDescription'] + '":"' + \
            appar['ApparatusHostName'] + terminator
        hostToChannelName = hostToChannelName + '"' + \
            appar['ApparatusHostName'] + '":"' + \
            appar['FormattedApparatusDescription'] + terminator
        streamAddressToChannelName = streamAddressToChannelName + '"' + \
            appar['StreamAddress'] + '":"' + \
            appar['FormattedApparatusDescription'] + terminator
        loopCount = loopCount + 1

    logger.debug('hostToAZ : ' + hostToAZ)
    logger.debug('hostToInstanceID : ' + hostToInstanceID)
    logger.debug('channelNameToHost : ' + channelNameToHost)
    logger.debug('hostToChannelName : ' + hostToChannelName)
    logger.debug('streamAddressToChannelName : ' + streamAddressToChannelName)

    # Create mapping of annotationname (for use in URL), with dict name (for use as payload data)
    annotationMapping = {
        'aws-host-to-availabilityzone': 'hostToAZ',
        'ort-orthost-to-availabilityzone': 'hostToAZ',
        'aws-host-to-instanceid': 'hostToInstanceID',
        'ort-orthost-to-instanceid': 'hostToInstanceID',
        'ort-channelname-to-orthost': 'channelNameToHost',
        'ort-host-to-channelname': 'hostToChannelName',
        'ort-streamaddress-to-channelname': 'streamAddressToChannelName'
    }
    logger.info('Data structure built!')

    # Post the data to inSITE!
    for annotationname, dictname in annotationMapping.items():
        try:
            annotationurl = 'https://'+hostname + \
                '/api/-/model/catalog/annotation/'+annotationname
            logger.info('Attempting to post annotation data (%s)' %
                        annotationurl)
            annotationrequest = insitesession.put(annotationurl, json=json.loads(
                locals()[dictname]), verify=False, timeout=15)
            annotationstatuscode = annotationrequest.status_code
            annotationtext = annotationrequest.text
        except requests.exceptions.Timeout:
            logger.error(
                'inSITE annotation post timed out connecting to (%s)' % annotationurl)
            sys.exit(1)
        except Exception as e:
            logger.error('inSITE annotation post (%s) threw an exception: %s' % (
                annotationurl, str(e)))
            sys.exit(1)
        else:
            if(annotationstatuscode == 200):
                if (annotationrequest.json().get('status', None) == 'ok'):
                    logger.info(
                        'inSITE annotation post (%s) succesfull!' % annotationurl)
                else:
                    logger.error(
                        'inSITE annotation post has returned an unacceptable response')
                    logger.error('Response: %s' % annotationtext)
                    sys.exit(1)
            else:
                logger.error('inSITE annotation post has returned an invalid response with status code (%s)' % str(
                    annotationstatuscode))
                logger.error('Response: %s' % annotationtext)
                sys.exit(1)


if __name__ == "__main__":
    # Try and login to inSITE. Required before we can post anything back to inSITE!
    def insiteLogin(hostname):
        try:
            logger.info(
                'Attempting to login to inSITE with host (%s)...' % hostname)
            loginurl = 'https://'+hostname+'/api/v1/login'
            loginrequest = insitesession.post(loginurl, json={
                                              'username': insiteUsername, 'password': insitePassword}, verify=False, timeout=15)
            loginstatuscode = loginrequest.status_code
            logintext = loginrequest.text
        except requests.exceptions.Timeout:
            logger.error(
                'inSITE login request timed out connecting to (%s)' % loginurl)
            return 1
        except Exception as e:
            logger.error(
                'inSITE login request threw an exception: %s' % str(e))
            return 1
        else:
            if(loginstatuscode == 200):
                if (loginrequest.json().get('status', None) == 'ok'):
                    logger.info('inSITE login succesfull!')
                    return 0
                else:
                    logger.error(
                        'inSITE login request has returned an unacceptable response')
                    logger.error('Response: %s' % logintext)
                    return 1
            else:
                logger.error('inSITE login request has returned an invalid response with status code (%s)' % str(
                    loginstatuscode))
                logger.error('Response: %s' % logintext)
                return 1

    # If we can login to the host, we assume it'll be safe to use for the posting aswell... This is the only place we try a different/subsequent hostname on failure.
    for hostname in insiteHostnames:
        if insiteLogin(hostname) == 0:
            processData()
            sys.exit(0)

    logger.error(
        'Unsucsessful login attempts to all inSITE hosts - Giving up...')
    sys.exit(1)
