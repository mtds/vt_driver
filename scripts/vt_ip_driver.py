#!/usr/bin/env python3

# VirusTotal v3 API - IP Address report driver

import configparser
from json import dumps
from objectpath import Tree
from sys import argv, exit
from urllib.request import urlopen, Request
from urllib.error import HTTPError

config = configparser.RawConfigParser()

if len(argv) < 3:
    print(argv[0] + ' -f <cfgfile> -i <ip_address>')
    exit(2)

for i in range(1, len(argv)):
    if argv[i] == '-h':
        print(argv[0] + ' -f <cfgfile> -i <ip_address>')
        exit(0)
    elif argv[i] == '-f' and i + 1 < len(argv):
        try:
            config.read(argv[i + 1])
        except configparser.ParsingError as err:
            print('ERROR: Could not parse config file:', err)
            exit(1)
        i += 1
    elif argv[i] == '-i' and i + 1 < len(argv):
        ip_target = argv[i + 1]
        i += 1

try:
    API_KEY = config.get('VirusTotal', 'API_KEY')
    full_report = config.getboolean('VirusTotal', 'full_report')
except configparser.NoSectionError as err:
    print('ERROR: Config file problem:', err)
    exit(1)

if 'ip_target' not in globals():
    print('ERROR: the -i parameter was not provided.')
    exit(2)

api_url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip_target
req = Request(api_url)
req.add_header('x-apikey', API_KEY)

try:
    with urlopen(req) as resp:
        data = resp.read().decode('utf-8')
        response = __import__('json').loads(data)
except HTTPError as e:
    if e.code == 204:
        print('WARNING: exceeded VirusTotal API rate limit (wait five minutes and try again).')
    else:
        print('ERROR: API request failed (HTTP', e.code, ')')
    exit(1)

tree = Tree(response)
data_obj = tree.execute('$.data')

if data_obj is None:
    print('No results found for IP:', ip_target)
    exit(0)

attributes = data_obj['attributes']
last_analysis_stats = attributes.get('last_analysis_stats', {})
malicious = last_analysis_stats.get('malicious', 0)
suspicious = last_analysis_stats.get('suspicious', 0)
total_engines = sum(last_analysis_stats.values())

if not config.getboolean('VirusTotal', 'quiet'):
    if full_report:
        print(dumps(response, sort_keys=False, indent=4))
    else:
        print('IP:', ip_target)
        print('Malicious:', malicious, '/', max(total_engines, 1))
        print('Suspicious:', suspicious)
        print('Reputation:', attributes.get('reputation', 'N/A'))
        print('Country:', attributes.get('country', 'N/A'))
        print('Tags:', ', '.join(attributes.get('tags', [])))