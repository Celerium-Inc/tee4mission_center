import datetime
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import jwt  # in PyJWT (not jwt on PyPI)
import requests
from var_dump import var_dump


class MissionCenter():
    def __init__(self, host, username, token, debug=False):
        self.host = host
        self.username = username
        self.token = token
        if debug:
            print(self.host, self.username, self.token)
        self.refresh_token()
        if debug:
            print(self.jwt_token)
        # Create the headers to send in the API request
        self.headers = {
            'Authorization': 'Bearer ' + str(self.jwt_token)
        }

    def refresh_token(self):
        # Create the payload for JWT authorization
        payload = {
            'exp': (datetime.datetime.utcnow() +
                    datetime.timedelta(seconds=310)),
            'sub': self.username
        }
        # Pass in your payload, shared secret, and encryption type to create your JWT
        self.jwt_token = jwt.encode(payload, self.token, 'HS256')

    def do_json_get_request(self, url):
        # Request the URL
        return requests.get(
            url,
            proxies={},
            headers=self.headers,
            # verify=True
        )

    def get_current_user(self):
        """Set group_id."""
        result = self.do_json_get_request(f'{self.host}/api/jsonws/security.currentuser/get-current-user')
        print(result)
        if result:
            try:
                var_dump(result)
                #group_id = result['compartments'][0]['groupId']
                #print(f'groupId: {group_id}')
                self.group_ids = [ _['groupId'] for _ in result.json()['compartments'] ]
            except KeyError as e:
                print('groupId not found in user data.')
        else:
            print('No result received from the API')

    def get_group_threads(self):
        if getattr(self, 'group_ids', None) is None or len(self.group_ids) == 0:
            self.get_current_user()
        #self.group_id = 39155

        for group_id in self.group_ids:
            url = f'{self.host}/api/jsonws/security.mbthread/get-group-threads?groupId={group_id}&subscribed=false&includeAnonymous=false&start=-1&end=-1'
            result = self.do_json_get_request(url)

            print(result)
            if result:

                try:
                    var_dump(result.json())
                    self.thread_ids = [_['threadId'] for _ in result.json()]
                except KeyError as e:
                    print('... not found in user data.')
            else:
                print('No result or bad status code received from the API.')

    def get_threat_extraction(self):
        if getattr(self, 'thread_ids', None) is None:
            self.get_group_threads()

        #self.group_id = 39155
        #self.category_id = 41863

        for thread_id in self.thread_ids:
            stix_url = f'{self.host}/api/jsonws/security.mbthread/get-thread?groupId={self.group_id}&categoryId={self.category_id}&threadId={thread_id}&includePosts=false&includeTE=true&teType=stix&postsDesc=true&xssScrape=false'
            result = self.do_json_get_request(stix_url)
            if result.status_code == 200:
                try:
                    # var_dump(result)
                    threat_extraction_string = result.json().get('threatExtraction', '')
                    if threat_extraction_string:
                        filename = f'./data/{result["threadId"]}.xml'
                        if not os.path.exists(filename):
                            with open(filename, 'w') as fh:
                                fh.write(threat_extraction_string)
                        else:
                            print('XML file exists. Skipping.')
                    else:
                        print(f'No threat extraction in thread_id: {thread_id}')
                except KeyError as e:
                    print('... not found in user data.')
            else:
                print(f'Bad status code ({result.status_code} received from the API in get_threat_extraction for thread_id: {thread_id}')


            json_url = f'{self.host}/api/jsonws/security.mbthread/get-thread?groupId={self.group_id}&categoryId={self.category_id}&threadId={thread_id}&includePosts=false&includeTE=true&teType=json&postsDesc=true&xssScrape=false'
            result = self.do_json_get_request(json_url)
            if result.status_code == 200:
                try:
                    # var_dump(result)
                    threat_extraction_string = result.json().get('threatExtraction', '')
                    if threat_extraction_string:
                        filename = f'./data/{result["threadId"]}.json'
                        if not os.path.exists(filename):
                            with open(filename, 'w') as fh:
                                fh.write(threat_extraction_string)
                        else:
                            print('JSON file exists. Skipping.')
                    else:
                        print(f'No threat extraction in thread_id: {thread_id}')
                except KeyError as e:
                    print('... not found in user data.')
            else:
                print(f'Bad status code ({result.status_code}) received from the API in get_threat_extraction for thread_id: {thread_id}')