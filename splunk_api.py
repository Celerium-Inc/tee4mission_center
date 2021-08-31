import base64
import json
import os
import urllib

import requests

from common import log


def splunk_upload_kv(data, filepath, threads_df, flags):
    """Upload KeyValue Lookups to Splunk Enterprise Security.

    Args:
        b64str: base64 encoded stix XML
        filepath: path and file name
        threads_df: pandas dataframe with thread details
        flags: abseil flags

    Returns:
        Boolean: Success/Failure
    """
    thread_id = int(os.path.splitext(os.path.split(filepath)[1])[0])
    row = threads_df.loc[threads_df['threadId'] == thread_id]
    root_message_id = row['rootMessageId'].values[0]
    subject = row['subject'].values[0]
    group_id = row['groupId'].values[0]
    category_id = row['categoryId'].values[0]
    description = f'{subject};{base64.b64encode(bytes(row.to_json(), "utf-8")).decode("utf-8")}'
    # ToDo: find a way to create the "friendly" versions of these URLs:
    # mc_url = f'{flags.mc_host}/group/{compartment_friendly_url}/{configurable_page_name}/-/message_boards/message/{root_message_id}'
    mc_url = f'{flags.mc_host}/group/{group_id}/{category_id}/-/message_boards/message/{root_message_id}'

    # ToDo: sort the observables by type and post the ones that use the same lookup_name together
    # ToDo: when should IP and Domain be combined into a single row?
    post_responses = []
    for observable in data.get('observables', {}).get('observables', []):
        items = []
        if observable.get('object'):  # False for Observable Compositions
            xsi_type = observable['object']['properties']['xsi:type']
            if xsi_type == 'AddressObjectType':
                if observable['object']['properties'].get('category') == 'e-mail':
                    value = observable['object']['properties']['address_value']
                    short_type = 'src_user'
                    lookup_name = 'email_intel'
                else:
                    value = observable['object']['properties']['address_value']
                    short_type = 'ip'
                    lookup_name = 'ip_intel'
            elif xsi_type == 'FileObjectType':
                value = observable['object']['properties']['hashes'][0][
                    'simple_hash_value'
                ]  # FixMe handle multiple hashes
                short_type = 'file_hash'
                lookup_name = 'file_intel'
            elif xsi_type == 'DomainNameObjectType':
                value = observable['object']['properties']['value']
                short_type = 'domain'
                # lookup_name = 'http_intel'  # "Atleast one important field of collection is required."
                lookup_name = 'ip_intel'
            elif xsi_type == 'URIObjectType':
                value = observable['object']['properties']['value']
                short_type = 'url'
                lookup_name = 'http_intel'
            else:
                log(flags, 'new type encountered: {xsi_type}. Skipping.')
                # import pdb; pdb.set_trace()
                continue

        items.append({short_type: value, "description": description, "threat_key": mc_url})

        joined_items = ','.join([json.dumps(item) for item in items])

        url = f'{flags.splunk_host}services/data/threat_intel/item/{lookup_name}'

        encoded = urllib.parse.quote_plus(f'[{joined_items}]')
        payload = f'item={encoded}'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        post_response = requests.request(
            "POST",
            url,
            auth=(flags.splunk_username, flags.splunk_password),
            headers=headers,
            data=payload,
            verify=flags.splunk_ssl_verify,
        )

        if post_response.status_code >= 300:
            log(flags, f'Failed POST: {post_response.__dict__}')

        log(flags, post_response.json().get('message'))

        post_responses.append(post_response.status_code < 300)

    return all(post_responses)


def splunk_es_upload_stix(b64str, filepath, flags):
    """Upload stix file to Splunk Enterprise Security (deprecated).

    Args:
        b64str: base64 encoded stix XML
        filepath: path and file name
        flags: abseil flags

    Returns:
        Boolean: Success/Failure
    """

    url = f'{flags.splunk_host}services/data/threat_intel/upload'

    _, filename = os.path.split(filepath)
    data = {
        'filename': f'__threat_{filename}',  # the prefix is an undocumented requirement for Splunk ES
        'content': b64str,
        'weight': '1',
        'overwrite': True,
        'sinkhole': False,
    }
    post_response = requests.post(
        url, json=data, auth=(flags.splunk_username, flags.splunk_password), verify=flags.splunk_ssl_verify,
    )
    log(flags, post_response.json().get('message'))
    return post_response.status_code < 300


def splunk_upload_stix(data, flags):
    """Upload stix file to Splunk Security Essentials.

    Args:
        data: JSON representation of the STIX object
        flags: abseil flags

    Returns:
        Boolean: Success/Failure
    """
    before_get_response = requests.get(
        f'{flags.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
        auth=(flags.splunk_username, flags.splunk_password),
        verify=flags.splunk_ssl_verify,
    )

    post_response = requests.post(
        f'{flags.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
        data=json.dumps(data),
        headers={'Content-Type': 'application/json'},
        auth=(flags.splunk_username, flags.splunk_password),
        verify=flags.splunk_ssl_verify,
    )
    # expect http 201
    new_keys = post_response.json()
    log(flags, f'Created key: {new_keys["_key"]}')

    if flags.debug:
        after_get_response = requests.get(
            f'{flags.splunk_host}servicesNS/nobody/Splunk_Security_Essentials/storage/collections/data/custom_content',
            auth=(flags.splunk_username, flags.splunk_password),
            verify=flags.splunk_ssl_verify,
        )
        after_keys = [_['_key'] for _ in after_get_response.json()]
        before_keys = [_['_key'] for _ in before_get_response.json()]
        log(flags, f'New keys added: {set(after_keys) - set(before_keys)}. N keys is now: {len(after_keys)}')

    return post_response.status_code < 300
