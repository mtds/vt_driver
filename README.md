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
- full_report: it could be 'true' or 'false', depending if the full report from VirusTotal is needed or not.
- hashlib_alg: hashing algorithms (available options are: sha1, sha256 or md5).

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

