import base64
import json
import os
import urllib

import requests

def splunk_es_lookup(data, filepath, threads_df, FLAGS):
    """Upload observbles to Splunk Enterprise Security Lookups.

    Args:
        b64str: base64 encoded stix XML
        filepath: path and file name
        threads_df: pandas dataframe with thread details
        FLAGS: abseil flags

    Returns:
        Boolean: Success/Failure
    """
    thread_id = int(os.path.splitext(os.path.split(filepath)[1])[0])
    row = threads_df.loc[threads_df['threadId'] == thread_id]
    root_message_id = row['rootMessageId'].values[0]
    subject = row['subject'].values[0]

    description = f'{subject};{base64.b64encode(bytes(row.to_json(), "utf-8")).decode("utf-8")}'

    compartment_friendly_url = 'threat-intel-center'
    configurable_page_name = 'cti-discussions'
    mc_url = f'{FLAGS.mc_host}/group/{compartment_friendly_url}/{configurable_page_name}/-/message_boards/message/{root_message_id}'

    api_url = f'{FLAGS.mc_host}/api/jsonws/security.mbthread/get-thread?groupId={{groupId}}&categoryId={{categoryId}}&threadId={{threadId}}&'

    #description = f"{subject};"

    threat_intel_collection = 'ip_intel'
    url = f'{FLAGS.splunk_host}services/data/threat_intel/item/{threat_intel_collection}'

    #_, filename = os.path.split(filepath)
    # embedded_domain, src_user, subject, file_hash, file_name, embedded_ip

    types = [_['object']['properties']['xsi:type'] for _ in data['observables']['observables'] if _.get('object')]
    

    address_value = data['observables']['observables'][6]['object']['properties']['address_value']
    domain_name0 = data['observables']['observables'][2]['object']['properties']['value']
    domain_name1 = data['observables']['observables'][3]['object']['properties']['value']
    items = [
        f'{{"ip": "{address_value}","description":"{description}","threat_key":"{mc_url}"}}',
        f'{{"domain":"{domain_name0}","description":"{description}","threat_key":"{mc_url}"}}',
        f'{{"domain":"{domain_name1}","description":"{description}","threat_key":"{mc_url}"}}',
    ]
    items = ','.join(items)

    encoded = urllib.parse.quote_plus(f'[{items}]')
    payload = f'item={encoded}'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    post_response = requests.request("POST",
                                url,
                                auth=(FLAGS.splunk_username, FLAGS.splunk_password),
                                headers=headers,
                                data=payload,
                                verify = FLAGS.splunk_ssl_verify,
                                )

    print(post_response.__dict__)
    import pdb; pdb.set_trace()

    if FLAGS.debug:
        print(post_response.json().get('message'))

    return post_response.status_code < 300

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
        url, json=data, auth=(FLAGS.splunk_username, FLAGS.splunk_password), verify=FLAGS.splunk_ssl_verify,
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
