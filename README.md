Description
===========

'vt_driver.py' is a small Python utility which rely on VirusTotal API  
in order to verify if a file was already identified as malware.

*NOTE*: in order to work this script needs a valid VirusTotal API key.

Usage
=====

```
python vt_driver.py malware_sample
```

The 'vt_config_template.cfg' has to be renamed as 'vt_config.cfg'  
the name of the configuration file is hardcoded in the script.

Available configuration parameters:

- API_KEY: to access the public API of VirusTotal a user has to be registered.
- quiet: if 'false' the script will not report any output.
- full_report: if 'true' and 'quiet' is set to 'false' then full report from VirusTotal will be printed.
- hashlib_alg: hashing algorithms (available options are: sha1, sha256 or md5).
- signature_gen: if 'true' a ClamAV compatibile signature archive will be generated.
- persistence: if 'true' the script will keep track of the submitted samples on a SQLite Db.
- name_prefix: a string used as a prefix for the ClamAV signature.

Internals
=========

VirusTotal API response code:

- if the item you searched for was not present in VirusTotal's dataset this result will be 0.
- if the requested item is still queued for analysis it will be -2.
- if the item was indeed present and it could be retrieved it will be 1.

- https://www.virustotal.com/en/documentation/public-api/#response-basics

Python requirements
===================

- Objectpath
- VirusTotal API

```
pip install objectpath
pip install virustotal-api
```

In order to run a quick test it would be easier to install those modules through _VirtualEnv_.

References
==========

- https://www.virustotal.com/en/documentation/public-api/
- https://pypi.python.org/pypi/virustotal-api
- https://pypi.python.org/pypi/objectpath

