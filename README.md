## Description

'__vt_driver.py__' is a small Python utility which rely on the [VirusTotal API](https://developers.virustotal.com/reference) in order to verify if a file was already identified as malware.

*API Key*: in order to work this script needs a valid VirusTotal API key, which can be obtained by registering yourself [here](https://www.virustotal.com/gui/join-us).

## Python 2 vs. 3

Starting from version tagged **0.5**, this script is meant to be executed using Python version **3.x**. Otherwise use the version tagged as **0.4**.

## Usage

```
>>> vt_driver.py -f config_file -s malware_sample
```

The template [config/vt_config_template.cfg](config/vt_config_template.cfg) can be used as a reference for your own config file.

Available configuration parameters are the following:

- *API_KEY*: to access the public or private API of VirusTotal a user has to be registered.
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

Reference: [VirusTotal API responses](https://developers.virustotal.com/reference#api-responses)

## Public vs Private VirusTotal API

Note that according to the [documentation](https://developers.virustotal.com/reference#public-vs-private-api), there are some explicit limits in using the Public API of VirusTotal:

* The Public API is limited to **4** requests per minute.
* The Public API must not be used in commercial products or services.
* The Private API returns more threat data and exposes more endpoints.
* The Private API is governed by an SLA that guarantees readiness of data.

## Required Python modules

- Objectpath
- SimpleJSON
- Python-Magic
- VirusTotal API

To install all the required modules:
```bash
>>> pip install -r requirements.txt
```

In order to run a quick test it would be easier to install the ``vt_driver.py`` script and its required modules in a virtual environment. Two methods are available:

* If you are using python 2.7.x, it's better to setup a virtual environment through [VirtualEnv](https://realpython.com/python-virtual-environments-a-primer/).
* If you are using python 3.x, the recommended way to setup a virtual environment is through [venv](https://docs.python.org/3/tutorial/venv.html).

## References

- [VirusTotal: getting started](https://developers.virustotal.com/reference#getting-started)
- [VirusTotal API on Pypi.org](https://pypi.org/project/virustotal-api)
- [ObjectPath: a NoSQL query language for semi-structured data](https://pypi.org/project/objectpath)
- [SimpleJSON: simple, fast, extensible JSON encoder/decoder for Python](https://pypi.org/project/simplejson/)
- [Python-Magic: file type identification using libmagic](https://pypi.org/project/python-magic/)
