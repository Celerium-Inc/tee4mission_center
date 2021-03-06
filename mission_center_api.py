import datetime
import os
import urllib3

import jwt  # in PyJWT (not jwt on PyPI)
import pandas as pd
import requests
from var_dump import var_dump

from common import log


class MissionCenter:
    def __init__(self, flags):
        self.flags = flags
        self.host = self.flags.mc_host
        self.username = self.flags.mc_username
        self.token = self.flags.mc_api_key

        if self.flags.mc_ssl_verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # data structures for tracking Mission Center Thread metadata; set by get_* methods
        self.group_ids = []
        self.thread_ids = {}  # keys are group_id, values are list of thread_ids

        # 3 below are (re)set by refresh_token()
        self.jwt_token_expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=310)
        self.jwt_token = None
        self.headers = None
        self.refresh_token()

    def refresh_token(self):
        # Create the payload for JWT authorization
        self.jwt_token_expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=310)
        payload = {'exp': self.jwt_token_expires, 'sub': self.username}
        # Pass in your payload, shared secret, and encryption type to create your JWT
        self.jwt_token = jwt.encode(payload, self.token, 'HS256')
        # Create the headers to send in the API request
        self.headers = {'Authorization': 'Bearer ' + str(self.jwt_token)}

    def _do_json_get_request(self, url):
        if self.jwt_token_expires < datetime.datetime.utcnow() + datetime.timedelta(seconds=5):
            self.refresh_token()
        # Request the URL
        return requests.get(url, proxies={}, headers=self.headers, verify=self.flags.mc_ssl_verify)

    def get_current_user(self):
        """Set group_id list to identify each of the Compartments."""
        result = self._do_json_get_request(f'{self.host}/api/jsonws/security.currentuser/get-current-user')
        if result.status_code == 200:
            log(self.flags, var_dump(result))
            # One and only one groupId for each Compartment
            self.group_ids = [_['groupId'] for _ in result.json().get('compartments', {})]
        else:
            log(self.flags, f'Bad status code ({result.status_code}) result received from the API')

    def get_categories(self, get_threads=False):
        if getattr(self, 'group_ids', None) is None or len(self.group_ids) == 0:
            self.get_current_user()

        category_records = []
        # for each Category(having a GroupID) in each Compartment, get the
        for group_id in self.group_ids:
            response = requests.get(
                f'{self.host}/api/jsonws/security.mbcategory/get-categories?groupId={group_id}&parentCategoryId=0&start=-1&end=-1',
                proxies={},
                headers=self.headers,
                verify=self.flags.mc_ssl_verify,
            )
            category_records.extend(response.json())

        categories_df = pd.DataFrame.from_records(category_records)

        # print the table and exit
        print(categories_df[['groupId', 'categoryId', 'name', 'description', 'threadCount', 'messageCount',]])

        # write the report to a CSV file
        pretty_date_str = (
            datetime.datetime.now().replace(microsecond=0).isoformat().replace('-', '').replace('T', '_').replace(':', '')
        )
        categories_df.to_csv(f'./reports/mission_center_categories_{self.username}_{pretty_date_str}.csv')

        if get_threads:
            threads = []
            for group_id in self.group_ids:
                print(f'working on group_id: {group_id}')
                result = requests.get(
                    f'{self.host}/api/jsonws/security.mbthread/get-group-threads?groupId={group_id}&start=-1&end=-1',
                    proxies={},
                    headers=self.headers,
                    verify=self.flags.mc_ssl_verify,
                )
                threads.extend(result.json())

            threads_df = pd.DataFrame.from_records(threads)
            threads_df = threads_df.reindex(
                columns=[
                    'companyId',
                    'groupId',
                    'categoryId',
                    'threadId',
                    'subject',
                    'rootMessageUser',
                    'messageCount',
                    'viewCount',
                    'lastPostByUser',
                    'lastPostDate',
                    'priority',
                    'posts',
                    'allowedReply',
                    'rootMessageId',
                ]
            )
            print(threads_df)  # Note: prints head,ellipsis,tail
            threads_df.to_csv(f'./reports/mission_center_threads_{self.username}_{pretty_date_str}.csv')
            return threads_df

    def get_group_threads(self):
        if getattr(self, 'group_ids', None) is None or len(self.group_ids) == 0:
            self.get_current_user()

        if self.flags.mc_include_categories:
            group_ids_to_do = set(self.group_ids).intersection(
                set([int(_.split(';')[0]) for _ in self.flags.mc_include_categories])
            )
        else:
            group_ids_to_do = self.group_ids

        for group_id in group_ids_to_do:
            url = f'{self.host}/api/jsonws/security.mbthread/get-group-threads?groupId={group_id}&start=-1&end=-1'
            result = self._do_json_get_request(url)
            if result.status_code == 200:
                all_threads = [_['threadId'] for _ in result.json()]
                if self.flags.mc_include_threads:
                    # only save the intersection with the configured threadIds
                    include_threads = [int(_) for _ in self.flags.mc_include_threads]
                    log(
                        self.flags, f'Only working on threads {include_threads} out of {all_threads} due to config flags.'
                    )
                    self.thread_ids[group_id] = list(set(all_threads).intersection(set(include_threads)))
                else:
                    self.thread_ids[group_id] = all_threads
            else:
                log(self.flags, f'Get Group Threads: Bad status code ({result.status_code}) for group_id: {group_id}.')

    def get_threat_extraction(self):
        """GET json/stix from Mission Center API and save to staging directory.

        Returns:
            None
        """
        if not getattr(self, 'thread_ids', None):
            self.get_group_threads()

        for group_id in self.thread_ids:
            for thread_id in self.thread_ids[group_id]:
                missing_threat_extraction = False
                for te_type in self.flags.mc_te_types:
                    if missing_threat_extraction:
                        log(self.flags, f'Skipping the {te_type} download b/c the previous type failed')
                        continue

                    log(self.flags, f'Working on {group_id},{thread_id},{te_type}')

                    staging_filename = f'./staging/{thread_id}.{te_type}'
                    complete_filename = f'./complete/{thread_id}.{te_type}'

                    if os.path.exists(complete_filename) or os.path.exists(staging_filename):
                        log(self.flags, f'{complete_filename} (or staging) exists. Skipping.')
                        continue

                    url = f'{self.host}/api/jsonws/security.mbthread/get-thread?&threadId={thread_id}&includePosts=false&includeTE=true&teType={te_type}&postsDesc=true&xssScrape=false'
                    result = self._do_json_get_request(url)
                    if result.status_code == 200:
                        threat_extraction_string = result.json().get('threatExtraction', '')
                        with open(staging_filename, 'w') as fh:
                            fh.write(threat_extraction_string)
                    else:
                        log(self.flags, f'Bad status code ({result.status_code} for thread_id: {thread_id}')
                        missing_threat_extraction = True
