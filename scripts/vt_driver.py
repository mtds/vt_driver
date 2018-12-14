#!/usr/bin/env python

#
# Test driver for VirusTotal public API.
#

# ver 0.4

import ConfigParser
import getopt
import hashlib
import magic
from json import dumps
from objectpath import *
from os import path
from sys import argv,exit
from virus_total_apis import PublicApi as VirusTotalPublicApi
from vt_persistence import check_Db,insert_Data,check_Record

# Initialize the parser:
config = ConfigParser.RawConfigParser()

# Read cmd line arguments:
try:
    opts, args = getopt.getopt(sys.argv[1:],"hf:s:")
except getopt.GetoptError, err:
    print str(err)
    print sys.argv[0] + ' -f <cfgfile> -s malware-sample'
    sys.exit(2) # UNIX convention: cmd line syntax error.

# Cycle through the arguments passed from cmd line:
for opt, arg in opts:
   if opt == '-h':
      print sys.argv[0] + ' -f <cfgfile> -s malware-sample'
      sys.exit(0)
   if opt == '-f':
      try:
          config.read(arg)
      except ConfigParser.ParsingError, err:
          print('ERROR: Could not parse:'), err
          sys.exit(1)
   if opt == '-s':
      sample = arg

# Get the VirusTotal API key and the hashing algorithm from the config file:
try:
    API_KEY = config.get('VirusTotal', 'API_KEY')
    hash_alg = config.get('VirusTotal','hashlib_alg')
except ConfigParser.NoSectionError, err:
    print('ERROR: Config file problem:'), err
    sys.exit(1)

# If 'sample' is not defined it means the '-s' parameter was not set correctly:
if not 'sample' in globals():
    print('ERROR: the -s parameter was not used.')
    sys.exit(2)

# Block sizes used to acquire the malware sample in binary format:
BLOCKSIZE = 65536

# Check if the malware sample exists:
if not path.exists(sample):
   print('ERROR: %s does not exist.' % sample)
   sys.exit(1)

# Get the file size in bytes:
# (used by ClamAV signatures)
file_size = path.getsize(sample)

# If it's an empty file don't go any further:
if file_size == 0:
    sys.exit('ERROR: %s size is 0 bytes.' % sample)
elif file_size > 33554432: # max 32MB for the API interface (https://www.virustotal.com/en/faq/)
    sys.exit('ERROR: %s size is bigger than 32 MB.' % sample)

# Determine filetype: (use python-magic)
file_type = magic.from_file(sample,mime=True)

# Define the hasher based on the Hash algorithms in the config file:
if hash_alg == 'sha1':
    hasher = hashlib.sha1()
elif hash_alg == 'sha256':
    hasher = hashlib.sha256()
else:
    hasher = hashlib.md5()

# Read the malware file in chunks:
with open(sample, "rb") as malware:
    buf = malware.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = malware.read(BLOCKSIZE)

# Get the hash of the sample in HEX format:
HASH_SAMPLE = hasher.hexdigest()

# Access the VT API:
vt = VirusTotalPublicApi(API_KEY)

# Get a full report (it's in JSON format):
response = vt.get_file_report(HASH_SAMPLE)

# Acquire the report results in JSON format:
tree=Tree(response)

# Check VT API usage rate limit:
if tree.execute("$.response_code") == 204:
    sys.exit('WARNING: exceeded VirusTotal API rate requests limit (wait five minutes and try again).')

# Extract the signature hash from the VT report:
# (Use ObjectPath to look for a specific key in the JSON tree)
sig_hash = tree.execute("$.results." + hash_alg)

# Check if the submitted sample hash is known on VirusTotal:
if tree.execute("$.results.response_code") == 1:

    if not config.getboolean('VirusTotal', 'quiet'):
        # It will (pretty) print the entire report in JSON format:
        if config.getboolean('VirusTotal', 'full_report'):
            print dumps(response, sort_keys=False, indent=4)
        else:
            # Just print the hash (in ASCII format) of the submitted file:
            print sig_hash

    # Create a ClamAV signature file:
    if config.getboolean('VirusTotal', 'signature_gen'):

        name_prefix = config.get('VirusTotal','name_prefix')

        # Build the signature string name: it uses the prefix name + file type + first 6 characters of the hash.
        sig_name = name_prefix+'.'+file_type.replace('/','_')+'.'+sig_hash[0:6]

        if config.getboolean('VirusTotal','persistence'):
            # Verify if the SQLite Db is available:
            check_Db()

            # Sample was already analyzed?
            if check_Record(sig_hash) is None:
                insert_Data(sig_hash,sig_name)
            else:
                sys.exit('WARNING: the submitted sample was already analyzed. Signature archive will not be updated.')

        if 'sha' in hash_alg:
            sig_file_name = name_prefix+'.hsb'
        else:
            sig_file_name = name_prefix+'.hdb'
        with open(sig_file_name, 'a') as sig_file:
            sig_file.write("%s:%s:%s\n" % (sig_hash,file_size,sig_name))
else:
    if not config.getboolean('VirusTotal', 'quiet'):
        print "No match for the submitted sample on VirusTotal."
        if config.getboolean('VirusTotal', 'full_report'):
            print dumps(response, sort_keys=False, indent=4)
