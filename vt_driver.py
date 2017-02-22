#!/usr/bin/env python

#
# Test driver for VirusTotal public API.
#

# ver 0.1

import ConfigParser
import json
import hashlib
import magic
import sys
import os
from objectpath import *
from virus_total_apis import PublicApi as VirusTotalPublicApi

#
# Read the VT public API Key from 'vt_config.cfg':
#
config = ConfigParser.RawConfigParser()
config.read('vt_config.cfg')

API_KEY = config.get('VirusTotal', 'API_KEY')

# Get the hashing algorithm:
hash_alg = config.get('VirusTotal','hashlib_alg')

# Block sizes used to acquire the malware sample in binary format:
BLOCKSIZE = 65536

#
# Get the malware filename from the cmd line:
#
if len(sys.argv) < 2:
    sys.exit('Usage: %s malware_file' % sys.argv[0])

if not os.path.exists(sys.argv[1]):
    sys.exit('ERROR: Malware sample %s was not found!' % sys.argv[1])

# Get the file size in bytes:
# (used by ClamAV signatures)
file_size = os.path.getsize(sys.argv[1])

# Determine filetype: (use python-magic)
file_type = magic.from_file(sys.argv[1],mime=True)

# Only binary files should be analyzed:
if (file_type == "text/plain"  or file_type == "ASCII text" ):
    sys.exit('%s is a %s file: it will not be submitted to VirusTotal.' % (sys.argv[1],file_type))

# Malware name: generate something like GSI_DateTime_FileType

# Signature: sha256|sha1|md5:FileSize:MalwareName

# Define the hasher based on the Hash algorithms in the config file:
if hash_alg == 'sha1':
    hasher = hashlib.sha1()
elif hash_alg == 'sha256':
    hasher = hashlib.sha256()
else:
    hasher = hashlib.md5()

# Read the malware file in chunks:
with open(sys.argv[1], "rb") as malware:
    buf = malware.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = malware.read(BLOCKSIZE)

# Get the hash of the sample in HEX format:
MW_SAMPLE = hasher.hexdigest()

# Access the VT API:
vt = VirusTotalPublicApi(API_KEY)

# Get a full report (it's in JSON format):
response = vt.get_file_report(MW_SAMPLE)

# Acquire the report results in JSON format:
tree=Tree(response)

# Check if the submitted sample hash is known on VirusTotal:
if tree.execute("$.results.response_code"):

    # It will (pretty) print the entire report in JSON format:
    if config.getboolean('VirusTotal', 'full_report'):
        print json.dumps(response, sort_keys=False, indent=4)
    else:
        # Use ObjectPath to look only for a specific key in the JSON tree:
        result = tree.execute("$.results." + hash_alg)
        # Just print the hash (in ASCII format) of the submitted file:
        print result
else:
    print "No match for the submitted sample on VirusTotal."
