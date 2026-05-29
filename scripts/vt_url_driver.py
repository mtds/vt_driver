#!/usr/bin/env python3

# VirusTotal v3 API - URL report driver

import configparser
import time
from json import dumps
from objectpath import Tree
from sys import argv, exit
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import urlencode

config = configparser.RawConfigParser()

if len(argv) < 3:
    print(argv[0] + ' -f <cfgfile> -u <url>')
    exit(2)

for i in range(1, len(argv)):
    if argv[i] == '-h':
        print(argv[0] + ' -f <cfgfile> -u <url>')
        exit(0)
    elif argv[i] == '-f' and i + 1 < len(argv):
        try:
            config.read(argv[i + 1])
        except configparser.ParsingError as err:
            print('ERROR: Could not parse config file:', err)
            exit(1)
        i += 1
    elif argv[i] == '-u' and i + 1 < len(argv):
        url_input = argv[i + 1]
        i += 1

try:
    API_KEY = config.get('VirusTotal', 'API_KEY')
except configparser.NoSectionError as err:
    print('ERROR: Config file problem:', err)
    exit(1)

full_report = config.getboolean('VirusTotal', 'full_report')

if 'url_input' not in globals():
    print('ERROR: the -u parameter was not provided.')
    exit(2)

# Step 1: Create URL analysis request
req = Request('https://www.virustotal.com/api/v3/urls')
req.add_header('x-apikey', API_KEY)
data = bytes(urlencode([('url', url_input)]), encoding='utf-8')

try:
    with urlopen(req, data) as resp:
        analysis_resp = __import__('json').loads(resp.read().decode('utf-8'))
except HTTPError as e:
    if e.code == 204:
        print('WARNING: exceeded VirusTotal API rate limit (wait five minutes and try again).')
    else:
        print('ERROR: API request failed (HTTP', e.code, ')')
    exit(1)

tree = Tree(analysis_resp)
analysis_id = tree.execute('$.data.id')

if not analysis_id:
    print('No analysis ID returned for URL:', url_input)
    exit(1)

# Step 2: Poll for analysis result
max_retries = 60
for attempt in range(max_retries):
    req2 = Request('https://www.virustotal.com/api/v3/analyses/' + analysis_id)
    req2.add_header('x-apikey', API_KEY)

    try:
        with urlopen(req2) as resp:
            response = __import__('json').loads(resp.read().decode('utf-8'))
    except HTTPError as e:
        if e.code == 204:
            print('WARNING: exceeded VirusTotal API rate limit (wait five minutes and try again).')
        else:
            print('ERROR: API request failed (HTTP', e.code, ')')
        exit(1)

    tree2 = Tree(response)
    status = tree2.execute('$.data.attributes.status')

    if status != 'queued':
        break

    time.sleep(1)
else:
    print('Timeout waiting for analysis to complete.')
    exit(1)

# Check if it has completed
data_obj2 = tree2.execute('$.data')
attributes = data_obj2['attributes']
status = attributes.get('status', '')

if status != 'completed':
    print('Analysis status:', status)
    exit(1)

last_analysis_stats = attributes.get('stats', {})
malicious = last_analysis_stats.get('malicious', 0)
suspicious = last_analysis_stats.get('suspicious', 0)
undetected = last_analysis_stats.get('undetected', 0)
harmless = last_analysis_stats.get('harmless', 0)
timeout = last_analysis_stats.get('timeout', 0)

if not config.getboolean('VirusTotal', 'quiet'):
    if full_report:
        print(dumps(response, sort_keys=False, indent=4))
    else:
        print('URL:', url_input)
        print('Malicious:', malicious)
        print('Suspicious:', suspicious)
        print('Harmless:', harmless)
        print('Undetected:', undetected)