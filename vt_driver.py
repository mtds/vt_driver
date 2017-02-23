#!/usr/bin/env python

#
# Test driver for VirusTotal public API.
#

# ver 0.2

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

# Extract the signature hash from the VT report:
# (Use ObjectPath to look for a specific key in the JSON tree)
sig_hash = tree.execute("$.results." + hash_alg)

# Check if the submitted sample hash is known on VirusTotal:
if tree.execute("$.results.response_code"):

    if not config.getboolean('VirusTotal', 'quiet'):
        # It will (pretty) print the entire report in JSON format:
        if config.getboolean('VirusTotal', 'full_report'):
            print json.dumps(response, sort_keys=False, indent=4)       
        else:
            # Just print the hash (in ASCII format) of the submitted file:
            print sig_hash

    # Create a ClamAV signature file:
    if config.getboolean('VirusTotal', 'signature_gen'):

        name_prefix = config.get('VirusTotal','name_prefix')

        # Build the signature string name: it uses the prefix name + file type + first 6 characters of the hash.
        sig_name = name_prefix+'.'+file_type.replace('/','_')+'.'+sig_hash[0:6]+'.UNOFFICIAL'

        if 'sha' in hash_alg:
            sig_file_name = name_prefix+'.hsb'
        else:
            sig_file_name = name_prefix+'.hdb'
        with open(sig_file_name, 'a') as sig_file:
            sig_file.write("%s:%s:%s\n" % (sig_hash,file_size,sig_name))
else:
    print "No match for the submitted sample on VirusTotal."
