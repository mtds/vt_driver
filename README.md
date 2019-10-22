## Description

'__vt_driver.py__' is a small Python utility which rely on the VirusTotal API in order to verify if a file was already identified as malware.

*API Key*: in order to work this script needs a valid VirusTotal API key, which can be obtained by registering [here.](https://www.virustotal.com/en/#signup)

## Usage

```
>>> vt_driver.py -f config_file -s malware_sample
```

The template [config/vt_config_template.cfg](config/vt_config_template.cfg) can be used as a reference for your own config file.

Available configuration parameters are the following:

- *API_KEY*: to access the public API of VirusTotal a user has to be registered.
- *quiet*: if 'false' the script will not report any output.
- *full_report*: if 'true' and 'quiet' is set to 'false' then full report from VirusTotal will be printed.
- *hashlib_alg*: hashing algorithms (available options are: sha1, sha256 or md5).
- *signature_gen*: if 'true' a ClamAV compatibile signature archive will be generated.
- *persistence*: if 'true' the script will keep track of the submitted samples on a SQLite Db.
- *name_prefix*: a string used as a prefix for the ClamAV signature.

## VirusTotal API

The internal behaviour of the script is based on the response code from the VirusTotal API:

- if the item you searched for was not present in VirusTotal's dataset this result will be **0**.
- if the requested item is still queued for analysis it will be **-2**.
- if the item was indeed present and it could be retrieved it will be **1**.

Reference: https://www.virustotal.com/en/documentation/public-api/#response-basics

## Python requirements

- Objectpath
- SimpleJSON
- Python-Magic
- VirusTotal API

```
pip install objectpath
pip install simplejson
pip install python-magic
pip install virustotal-api
```

In order to run a quick test it would be easier to install those modules through _VirtualEnv_.

## References

- https://www.virustotal.com/en/documentation/public-api/
- https://pypi.org/project/virustotal-api
- https://pypi.org/project/objectpath
- https://pypi.org/project/simplejson/
- https://pypi.org/project/python-magic/
