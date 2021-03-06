[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tee4mission_center&metric=alert_status&token=1f89b08748c5afd74a4f4706ad0c0a7d84d8eed7)](https://sonarcloud.io/dashboard?id=tee4mission_center)

# Threat Extraction Engine for Mission Center

Mission Center has "Threat Extraction" into STIX XML/JSON files associated with threads.  This "Threat Extraction Engine" enumerates all of the threads accessible to the user (who’s API Keys are used) and then downloads the XML (and/or JSON representataion) for each thread to a local directory (./staging).

If only a subset of the threads' STIX is desired, the list of Thread IDs and/or Category IDs may be specified.  The reporting features may be used to find those IDs. 

## Screencasts


| Part 1: Download from Mission Center and upload to MISP | Part 2: Upload to Splunk Enterprise Security |
| ----------- | ----------- |
| [![Alt text](https://img.youtube.com/vi/g3CzOFR0Ab0/0.jpg)](https://www.youtube.com/watch?v=g3CzOFR0Ab0)      | [![Alt text](https://img.youtube.com/vi/npg2QqSJDo8/0.jpg)](https://www.youtube.com/watch?v=npg2QqSJDo8)  |

## MISP

If the MISP config settings are present, the script submits the downloaded STIX to the MISP Instance.  The files successfully uploaded are moved from the `staging/` directory, to the `complete/` directory.

## Splunk Enterprise Security

If the Splunk config settings are present and `--splunk_es` (Enterprise Security) is True (the default), the script submits the downloaded STIX to the Splunk ES Instance’s /data/threat_intel/upload API.  The files successfully uploaded are moved from the `staging/` directory, to the `complete/` directory.


## Splunk Security Essentials

If the Splunk config settings are present and `--splunk_es` (Enterprise Security) is False, the script submits the downloaded JSON to the Splunk Instance’s `Splunk_Security_Essentials/storage/collections/data/custom_content` API.  The JSON files successfully uploaded are moved from the `staging/` directory, to the `complete/` directory.


# Requirements

## Install requirements in a virtual environment
```
$ python3 -m venv ./venv/
$ source ./venv/bin/activate
(venv) $ pip install -r requirements.txt
```

## Verify requirements are met
```
(venv) $ pip show pymisp
Name: pymisp
Version: 2.4.144
Summary: Python API for MISP.
Home-page: https://github.com/MISP/PyMISP
Author: Raphaël Vinot
Author-email: raphael.vinot@circl.lu
License: BSD-2-Clause
Location: /Users/ddye/Projects/mission_center2splunk/venv/lib/python3.7/site-packages
Requires: python-dateutil, jsonschema, requests, deprecated
Required-by:
```


# Configuration

This utility uses Abseil's flags (aka gflags):
https://abseil.io/docs/python/guides/flags

Although you can specify the flags from the command line interface (CLI), it is easiest to put them 
into a file and then specify that file with `--flagfile` (see Example below).

An example config file is provided: `tee4mission_center.cfg.example`

NOTE: When mixing CLI and `--flagfile`, order is important: CLI flags should be *after* the `--flagfile`:
```
python tee4mission_center.py --flagfile=tee4mission_center.cfg --debug=False  # Yes

python tee4mission_center.py --debug=False --flagfile=tee4mission_center.cfg  # No
```

# Usage

```
(venv) $ python tee4mission_center.py --help

       USAGE: tee4mission_center.py [flags]
flags:

tee4mission_center.py:
  --[no]debug: Produces debugging output
    (default: 'false')
  --mc_api_key: Mission Center API Token
    (default: '')
  --[no]mc_get_categories: Get Mission Center Categories, write a report, and exit
    (default: 'false')
  --[no]mc_get_threads: Get Mission Center Threads, write a report, and exit
    (default: 'false')
  --mc_host: Mission Center Host
    (default: '')
  --mc_include_categories: Specify list of `groupId;categoryId,...` to upload
    (a comma separated list)
  --mc_include_threads: Specify list of `threadId,...` to upload
    (a comma separated list)
  --[no]mc_only_extract: Extract to staging/ and skip uploading.
    (default: 'false')
  --[no]mc_only_upload: Upload from staging/ without checking for new extractions.
    (default: 'false')
  --[no]mc_ssl_verify: Mission Center SSL Verify
    (default: 'true')
  --mc_te_types: Mission Center Threat Extraction file types
    (default: 'stix,json')
    (a comma separated list)
  --mc_username: Mission Center Username
    (default: '')
  --misp_api_key: MISP API Token
    (default: '')
  --misp_host: MISP Host
    (default: '')
  --[no]misp_ssl_verify: MISP SSL Verify
    (default: 'true')
  --[no]splunk_es: Splunk Enterprise Security
    (default: 'true')
  --splunk_host: Splunk Host
    (default: '')
  --splunk_password: Splunk Password
    (default: '')
  --[no]splunk_ssl_verify: Splunk SSL Verify
    (default: 'true')
  --splunk_username: Splunk Username
    (default: '')

Try --helpfull to get a list of all flags.
```

# Example
```
(venv) $ python tee4mission_center.py --flagfile tee4mission_center.cfg  --debug=True
https://missioncenter.celeriumd.net ddye <api key redacted>
<jwt token redacted>
{'firstName': 'Dan', 'middleName': '', 'lastName': 'Dye', 'screenName': 'ddye', 'emailAddress': 'ddye@celerium.com', ...
#0 dict(15)
    ['firstName'] => str(3) "Dan"
    ['middleName'] => str(0) ""
    ['lastName'] => str(3) "Dye"
    ['screenName'] => str(4) "ddye"
    ['emailAddress'] => str(17) "ddye@celerium.com"
    ['greeting'] => str(16) "Welcome Dan Dye!"
    ['jobTitle'] => str(0) ""
    ['createDate'] => str(19) "2021-06-18T00:51:51"
    ['modifiedDate'] => str(19) "2021-07-15T19:03:46"
    ['timeZoneId'] => str(3) "UTC"
    ['languageId'] => str(5) "en_US"
    ['companyId'] => int(20116)
    ['compartments'] => list(5)
        [0] => dict(7)
            ['name'] => str(0) ""
            ['description'] => str(0) ""
            ['friendlyURL'] => str(5) "/ddye"
            ['groupId'] => int(16084773)
            ['parentGroupId'] => int(0)
            ['entityCacheEnabled'] => bool(True)
            ['finderCacheEnabled'] => bool(True)
        [1] => dict(7)
            ['name'] => str(138) "<?xml version='1.0' encoding='UTF-8'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Guest</Name></root>"
            ['description'] => str(0) ""
            ['friendlyURL'] => str(6) "/guest"
            ['groupId'] => int(20143)
            ['parentGroupId'] => int(0)
            ['entityCacheEnabled'] => bool(True)
            ['finderCacheEnabled'] => bool(True)
        [2] => dict(7)
            ['name'] => str(152) "<?xml version='1.0' encoding='UTF-8'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Threat Intel Center</Name></root>"
            ['description'] => str(0) ""
            ['friendlyURL'] => str(20) "/threat-intel-center"
            ['groupId'] => int(39155)
            ['parentGroupId'] => int(0)
            ['entityCacheEnabled'] => bool(True)
            ['finderCacheEnabled'] => bool(True)
    ['entityCacheEnabled'] => bool(True)
    ['finderCacheEnabled'] => bool(True)
groupId: 16084773
(venv) $
```

# Reporting Features

## Get Categories
Print and write a csv to reports/.  These reports facilitate extraction only from specified Categories (shown below).
```
(venv) $ python tee4mission_center.py --flagfile=tee4mission_center.cfg --mc_get_categories=True
```

```
   groupId  categoryId                       name                                        description  threadCount  messageCount
0    20143    15385863               Karla TE OFF                                            asdfsdf            1             1
1    20143    15269554                Karla TE ON                                                tes            8            12
2    20143    15547858          Karla with CFs on                                   Custom Field Cat            1             3
3    20143    15713742         SM Test Cat1 TE on                                                               1             1
4    39155       41749             Admin Category                         Admins private Discussions            1             4
5    39155    15099024    Bitcoin Threat Payments  This category tracks several different forms o...            2             7
6    39155    15025359                Latest IOCs                                                              53           150
7    39155       41863          SMB Working Group  Discussion of the latest CTI in our SMB community            9            31
8    39155    15034825  Threat Intel Mailing List  Mailing LIst to discuss modern Threat Intellig...           62            76
```

### Extract from only two categories

Specify the groupId with each categoryId like so:
`'groupId;categoryId,groupId;categoryId'`

Note the single quotes around the value when using CLI flags.

Upload only the "Latest IOCs" and "Threat Intel Mailing List" categories:
```
(venv) $ python tee4mission_center.py --flagfile=tee4mission_center.cfg --mc_include_categories='39155;15025359,39155;15034825'
```


## Get Threads
Print and write a csv to reports/.  These reports facilitate extraction only from specified Threads (shown below).
```
(venv) $ python tee4mission_center.py --flagfile=tee4mission_center.cfg --debug=False --mc_get_threads=True
```

```
   groupId  categoryId                       name                                        description  threadCount  messageCount
0    20143    15385863               Karla TE OFF                                            asdfsdf            1             1
1    20143    15269554                Karla TE ON                                                tes            8            12
2    20143    15547858          Karla with CFs on                                   Custom Field Cat            1             3
3    20143    15713742         SM Test Cat1 TE on                                                               1             1
4    39155       41749             Admin Category                         Admins private Discussions            1             4
5    39155    15099024    Bitcoin Threat Payments  This category tracks several different forms o...            2             7
6    39155    15025359                Latest IOCs                                                              53           150
7    39155       41863          SMB Working Group  Discussion of the latest CTI in our SMB community            9            31
8    39155    15034825  Threat Intel Mailing List  Mailing LIst to discuss modern Threat Intellig...           62            76
working on group_id: 16084773
working on group_id: 20143
working on group_id: 39155
working on group_id: 15049013
working on group_id: 15797460
     companyId   groupId  categoryId  threadId                                    subject             rootMessageUser  messageCount  viewCount              lastPostByUser         lastPostDate  priority posts  allowedReply  rootMessageId
0        20116     20143           0  15927301                              test test 123      {'name': 'Karla Rice'}             1          2      {'name': 'Karla Rice'}  2021-02-19T23:15:51       0.0    []          True       15927300
1        20116     20143    15269554  15713783                 SM Thread1 Cat Karla TE ON  {'name': 'Samir Mishiyev'}             1          8  {'name': 'Samir Mishiyev'}  2020-08-11T22:50:39       0.0    []          True       15713782
2        20116     20143    15713742  15713754                            SM Thread1 Cat1  {'name': 'Samir Mishiyev'}             1         14  {'name': 'Samir Mishiyev'}  2020-08-11T22:49:10       0.0    []          True       15713753
3        20116     20143    15547858  15547915                         Karla testing 3-12      {'name': 'Karla Rice'}             3          8      {'name': 'Karla Rice'}  2020-03-11T15:11:13       0.0    []          True       15547914
4        20116     20143           0  15427092                            karla test url2      {'name': 'Karla Rice'}             1         12      {'name': 'Karla Rice'}  2019-10-16T14:47:27       0.0    []          True       15427091
..         ...       ...         ...       ...                                        ...                         ...           ...        ...                         ...                  ...       ...   ...           ...            ...
191      20116     39155       41863     42341                              Peyta Malware    {'name': 'Matthew Loew'}             1         56    {'name': 'Matthew Loew'}  2018-03-13T16:13:52       0.0    []          True          42340
192      20116  15049013           0  15114570  URLs and Domains - Does Search Find them?   {'name': 'Chrissy Hines'}            10         50  {'name': 'Rajesh Goswami'}  2019-01-24T13:57:44       0.0    []          True       15114569
193      20116  15049013           0  15114557                  incident y and subsidiary   {'name': 'Chrissy Hines'}             1          6   {'name': 'Chrissy Hines'}  2019-01-16T01:19:37       0.0    []          True       15114556
194      20116  15049013           0  15114545                  incident y and subsidiary   {'name': 'Chrissy Hines'}             1          4   {'name': 'Chrissy Hines'}  2019-01-16T01:19:17       0.0    []          True       15114544
195      20116  15049013           0  15114525                                 incident X   {'name': 'Chrissy Hines'}             1          4   {'name': 'Chrissy Hines'}  2019-01-16T01:18:25       0.0    []          True       15114524

[196 rows x 14 columns]
```

Upload only the "Peyta Malware" and "incident X" threads:
```
(venv) $ python tee4mission_center.py --flagfile=tee4mission_center.cfg --mc_include_threads='42341,15114525'
```

# Upload to MISP
```
python tee4mission_center.py --flagfile=tee4mission_center.cfg \
 --misp_host=https://localhost:8443/
 --misp_api_key=dMo...redacted...sU
 --misp_ssl_verify=False
```

# Upload to Splunk Enterprise Security (ES)

```
python tee4mission_center.py --flagfile=tee4mission_center.cfg \
 --splunk_host=https://es-celerium.splunkcloud.com:8089/ \
 --splunk_username=DanD \
 --splunk_password=redacted \
 --splunk_es=True \
 --splunk_ssl_verify=False 
```

# Upload to Splunk Security Essentials

If Splunk ES is not available, the JSON representation of the stix file can be uploaded to Splunk Security Essentials
```
python tee4mission_center.py --flagfile=tee4mission_center.cfg \
 --splunk_host=https://es-celerium.splunkcloud.com:8089/ \
 --splunk_username=DanD \
 --splunk_password=redacted \
 --splunk_es=False \
 --splunk_ssl_verify=False 
```
