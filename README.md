
# Requirements

## Install requirements in a virtual environment
```
$ python3 -m venv ./venv/
$ source ./venv/bin/activate
(venv) $ pip install -r requirements.txt
```

## Verify Requirements are Met
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


# Usage

```
(mission_center2splunk_misp) $ python main.py --help

       USAGE: main.py [flags]
flags:

main.py:
  --[no]debug: Produces debugging output
    (default: 'false')
  --misp_api_key: MISP API Token
    (default: '')
  --misp_host: MISP Host
    (default: '')
  --[no]misp_ssl_verify: SSL Verify
    (default: 'true')
  --ms_api_key: API Token
    (default: '')
  --ms_host: Mission Center Host
    (default: 'https://missioncenter.celeriumd.net')
  --ms_username: Username
    (default: '')
  --thread_id: Thread ID
    (default: '16121783')

Try --helpfull to get a list of all flags.
```

# Example
```
(mission_center2splunk_misp) $ python main.py --flagfile mission_center2splunk.cfg
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
        [3] => dict(7)
            ['name'] => str(157) "<?xml version='1.0' encoding='UTF-8'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Billington International</Name></root>"
            ['description'] => str(0) ""
            ['friendlyURL'] => str(10) "/auto-isac"
            ['groupId'] => int(15049013)
            ['parentGroupId'] => int(0)
            ['entityCacheEnabled'] => bool(True)
            ['finderCacheEnabled'] => bool(True)
        [4] => dict(7)
            ['name'] => str(152) "<?xml version='1.0' encoding='UTF-8'?><root available-locales="en_US" default-locale="en_US"><Name language-id="en_US">Day &amp; Zimmerman</Name></root>"
            ['description'] => str(0) ""
            ['friendlyURL'] => str(14) "/day-zimmerman"
            ['groupId'] => int(15797460)
            ['parentGroupId'] => int(0)
            ['entityCacheEnabled'] => bool(True)
            ['finderCacheEnabled'] => bool(True)
    ['entityCacheEnabled'] => bool(True)
    ['finderCacheEnabled'] => bool(True)
groupId: 16084773
(mission_center2splunk)  ddye@cornix  ~/Projects/mission_center2splunk   main 
```