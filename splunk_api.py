import json
import os

import requests


def splunk_es_upload_stix(b64str, filepath, FLAGS):
    """Upload stix file to Splunk Enterprise Security.

    Args:
        b64str: base64 encoded stix XML
        filepath: path and file name
        FLAGS: abseil flags

    Returns:
        Boolean: Success/Failure
    """
    url = f'{FLAGS.splunk_host}services/data/threat_intel/upload'
    _, filename = os.path.split(filepath)
    data = {
        'filename': f'__threat_{filename}',  # the prefix is an undocumented requirement for Splunk ES
        'content': b64str,
        'weight': '1',
        'overwrite': True,
        'sinkhole': False,
    }
    post_response = requests.post(
        url,
        json=data,
        auth=(FLAGS.splunk_username, FLAGS.splunk_password),
        verify=FLAGS.splunk_ssl_verify,
    )
    if FLAGS.debug:
        print(post_response.json().get('message'))
    return post_response.status_code < 300


def splunk_upload_stix(data, FLAGS):
    """Upload stix file to Splunk Security Essentials.

    Args:
        data: JSON representation of the STIX object
        FLAGS: abseil flags

    Returns:
        Boolean: Success/Failure
    """
    before_get_response = requests.get(
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
    print(f'Created key: {new_keys["_key"]}')

    if FLAGS.debug:
        after_get_response = requests.get(
            f'{FLAGS.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
            auth=(FLAGS.splunk_username, FLAGS.splunk_password),
            verify=FLAGS.splunk_ssl_verify,
        )
        after_keys = [_['_key'] for _ in after_get_response.json()]
        before_keys = [_['_key'] for _ in before_get_response.json()]
        print(f'New keys added: {set(after_keys) - set(before_keys)}. N keys is now: {len(after_keys)}')
    return post_response.status_code < 300
