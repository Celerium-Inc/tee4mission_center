
# Mission Center Integrations Script

Mission Center has STIX XML files associated with threads.  This script enumerates all of the threads accessible to the user (who’s API Keys are used) and then downloads the XML (and JSON version) for each thread to a local directory (./staging).

## MISP

After downloading the XML from Mission Center, when the MISP config settings are present, the script submits STIX1 to the MISP Instance.

## Splunk Enterprise Security (Future Work)

After downloading the XML from Mission Center, when the Splunk config settings are present, the script submits STIX1 to the Splunk ES Instance’s /data/threat_intel/upload API.

## Splunk Splunk Security Essentials

After downloading the JSON from Mission Center, when the Splunk config settings are present, the script submits the JSON to the Splunk Instance’s Splunk_Security_Essentials/storage/collections/data/custom_content API.


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

An example config file is provided: `mission_center2splunk.cfg.example`

NOTE: When mixing CLI and `--flagfile`, order is important: CLI flags should be *after* the `--flagfile`:
```
python main.py --flagfile=mission_center2splunk.cfg --debug=False  # Yes

python main.py --debug=False --flagfile=mission_center2splunk.cfg  # No
```

# Usage

```
(venv) $ python main.py --help

       USAGE: main.py [flags]
flags:

main.py:
  --[no]debug: Produces debugging output
    (default: 'false')
  --mc_api_key: Mission Center API Token
    (default: '')
  --[no]mc_get_categories: Get Mission Center Categories, write a report, and exit
    (default: 'false')
  --[no]mc_get_threads: Get Mission Center Threads,write a report, and exit
    (default: 'false')
  --mc_host: Mission Center Host
    (default: 'https://missioncenter.celeriumd.net')
  --mc_include_categories: Specify list of `groupId;categoryId,...` to upload
    (a comma separated list)
  --mc_include_threads: Specify list of `threadId,...` to upload
    (a comma separated list)
  --[no]mc_ssl_verify: Mission Center SSL Verify
    (default: 'true')
  --mc_username: Mission Center Username
    (default: '')
  --misp_api_key: MISP API Token
    (default: '')
  --misp_host: MISP Host
    (default: '')
  --[no]misp_ssl_verify: MISP SSL Verify
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
(venv) $ python main.py --flagfile mission_center2splunk.cfg
https://missioncenter.celeriumd.net ddye <api key redacted>
<jwt token redacted>
{'firstName': 'Dan', 'middleName': '', 'lastName': 'Dye', 'screenName': 'ddye', 'emailAddress': 'ddye@celerium.com', 'greeting': 'Welcome Dan Dye!', 'jobTitle': '', 'createDate': '2021-06-18T00:51:51', 'modifiedDate': '2021-07-15T19:03:46', 'timeZoneId': 'UTC', 'languageId': 'en_US', 'companyId': 20116, 'compartments': [{'name': '', 'description': '', 'friendlyURL': '/ddye', 'groupId': 16084773, 'parentGroupId': 0, 'entityCacheEnabled': True, 'finderCacheEnabled': True}, {'name': '<?xml version=\'1.0\' encoding=\'UTF-8\'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Guest</Name></root>', 'description': '', 'friendlyURL': '/guest', 'groupId': 20143, 'parentGroupId': 0, 'entityCacheEnabled': True, 'finderCacheEnabled': True}, {'name': '<?xml version=\'1.0\' encoding=\'UTF-8\'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Threat Intel Center</Name></root>', 'description': '', 'friendlyURL': '/threat-intel-center', 'groupId': 39155, 'parentGroupId': 0, 'entityCacheEnabled': True, 'finderCacheEnabled': True}, {'name': '<?xml version=\'1.0\' encoding=\'UTF-8\'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Billington International</Name></root>', 'description': '', 'friendlyURL': '/auto-isac', 'groupId': 15049013, 'parentGroupId': 0, 'entityCacheEnabled': True, 'finderCacheEnabled': True}, {'name': '<?xml version=\'1.0\' encoding=\'UTF-8\'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Day &amp; Zimmerman</Name></root>', 'description': '', 'friendlyURL': '/day-zimmerman', 'groupId': 15797460, 'parentGroupId': 0, 'entityCacheEnabled': True, 'finderCacheEnabled': True}], 'entityCacheEnabled': True, 'finderCacheEnabled': True}
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

```
(venv) $ python main.py --mc_get_categories=True --flagfile=mission_center2splunk.cfg
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


## Get Threads

```
(venv) $ python main.py --flagfile=mission_center2splunk.cfg --debug=False --mc_get_threads=True
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


Use those reports to limit which groups/categoriesthreads to upload


Upload only the "Latest IOCs" and "Threat Intel Mailing List" categories:
```
(venv) $ python main.py --flagfile=mission_center2splunk.cfg --mc_include_categories='39155;15025359,39155;15034825'
```

Upload only the "Peyta Malware" and "incident X" threads:
```
(venv) $ python main.py --flagfile=mission_center2splunk.cfg --mc_include_threads='42341,15114525'
```