import datetime

import jwt  # in PyJWT (not jwt on PyPI)
import requests
from var_dump import var_dump


class MissionCenter():
    def __init__(self, host, username, token):
        self.host = host
        self.username = username
        self.token = token

        print(self.host, self.username, self.token)
        self.refresh_token()
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
        response = requests.get(
            url,
            proxies={},
            headers=self.headers,
            # verify=True
        )
        if response.status_code == 200:
            return response.json()
        else:
            print('Received non-200 status code: '
                  '{}'.format(response.status_code))
            return response

    def get_current_user(self):
        result = self.do_json_get_request(f'{self.host}/api/jsonws/security.currentuser/get-current-user')
        print(result)
        if result:
            try:
                var_dump(result)
                group_id = result['compartments'][0]['groupId']
                print(f'groupId: {group_id}')
            except KeyError as e:
                print('groupId not found in user data.')
        else:
            print('No result received from the API')