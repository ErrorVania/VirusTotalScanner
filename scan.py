#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import json
import sys

# ------------------------------CHECK FOR ARGS------------------------------

#if len(sys.argv) < 2:
#    print 'USAGE: ' + sys.argv[0] \
#        + ' [VIRUSTOTAL APIKEY] [FILENAME OR URL] [Action (F for File and U for URL)]'
#    sys.exit()

# ------------------------------DEFINE URL VARIABLES------------------------------

URL_sendFile      = 'https://www.virustotal.com/vtapi/v2/file/scan'
URL_getReport     = 'https://www.virustotal.com/vtapi/v2/file/report'
URL_scanURL       = 'https://www.virustotal.com/vtapi/v2/url/scan'
URL_getURLresults = 'http://www.virustotal.com/vtapi/v2/url/report'
URL_getIPscan     = 'http://www.virustotal.com/vtapi/v2/ip-address/report'

# ------------------------------DEFINE REQUIRED VARIABLES------------------------------


apikey = raw_input('API KEY: ')


if apikey == 'd':
    apikey = 'c876f0a902c7e079b3387de2d9aeb90c55478f16b81fe782be502dbd9a5118e9'


input_str = raw_input('SCAN FILE OR URL? [F/U]: ')














headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'gzip,  My Python requests library example client or username'}
if input_str == 'F':
    filename = raw_input('ENTER YOUR FILE: ')
    files = {'file': (filename, open(filename, 'rb'))}

    # ------------------------------SEND FILE------------------------------

    params_Send = {'apikey': apikey}
    response_Send = requests.post(URL_sendFile, files=files, params=params_Send)
    json_response = response_Send.json()

    # ------------------------------RETRIEVE SCAN DATA------------------------------

    params_Scan = {'apikey': apikey, 'resource': json_response['resource']}
    response_Scan = requests.get(URL_getReport, params=params_Scan, headers=headers)
    scan_response = response_Scan.json()

    # ------------------------------PRINT OUTPUT------------------------------

    print '------------------------------DISPLAYING RESULTS------------------------------'
    print '[#] RESOURCE:  {}'.format(json_response['resource'])
    if 'positives' in scan_response:
        positives = str(scan_response['positives'])
        total = str(scan_response['total'])
        print '[#] RESULTS:   {0}/{1}'.format(positives, total)

    # ------------------------------PRINT DETECTIONS------------------------------

    try:
        for x in scan_response['scans']:
            if scan_response['scans'][x]['detected'] == True:
                y = "'" + scan_response['scans'][x]['result'] + "'"
                print '[#] {0} has detected: {1}'.format(x, y)
    except:
            print 'An Error has occured, this is either the result of the recieved JSON not containing the "scans" parameter, or that the File is safe.'

# ------------------------------URL SCAN------------------------------










if input_str == 'U':
    params = {'apikey': apikey, 'url': raw_input('URL: ')}
    response = requests.post(URL_scanURL, data=params)
    send_response = response.json()

    params = {'apikey': apikey, 'resource': send_response['resource']}
    response = requests.post(URL_getURLresults, params=params, headers=headers)
    result_response = response.json()
    print '------------------------------DISPLAYING RESULTS------------------------------'
    print '[#] RESOURCE:  {}'.format(send_response['resource'])
    if 'positives' in result_response:
        positives = str(result_response['positives'])
        total = str(result_response['total'])
        print '[#] RESULTS:   {0}/{1}'.format(positives, total)

    for x in result_response['scans']:
        if result_response['scans'][x]['detected'] == True:
            y = "'" + result_response['scans'][x]['result'] + "'"
            print '[#] {0} has detected: {1}'.format("'" + x + "'", y)



