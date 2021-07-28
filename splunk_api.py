import json

import requests


def splunk_upload_stix(data, FLAGS):
    get_response = requests.get(
        f'{FLAGS.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
        auth=(FLAGS.splunk_username, FLAGS.splunk_password),
        verify=FLAGS.splunk_ssl_verify,
    )

    post_response = requests.post(
        f'{FLAGS.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
        data=json.dumps(data),
        headers={'Content-Type': 'application/json'},
        auth=(FLAGS.splunk_username, FLAGS.splunk_password),
        verify=FLAGS.splunk_ssl_verify,
    )
    # expect http 201
    new_keys = post_response.json()


