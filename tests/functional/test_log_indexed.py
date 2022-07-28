# Copyright (2016) Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import config
import datetime
import json
import os
import random
import requests
import string
import subprocess
import time
import urllib.request
import yaml

from utils import Base, skipIfServiceMissing, skipReason, is_present
from utils import set_private_key
from utils import GerritGitUtils

elasticsearch_credential_file = \
    '/var/lib/software-factory/bootstrap-data/secrets.yaml'
sfconfig_file = '/etc/software-factory/sfconfig.yaml'


# TODO move all HTTP queries to requests, instead of creating cURL scripts.


class TestLogExportedInElasticSearch(Base):
    """ Functional tests to verify job logs are exported in ElasticSearch
    """

    def setUp(self):
        super(TestLogExportedInElasticSearch, self).setUp()
        priv_key_path = set_private_key(
            config.USERS[config.ADMIN_USER]["privkey"])
        self.gitu_admin = GerritGitUtils(
            config.ADMIN_USER, priv_key_path,
            config.USERS[config.ADMIN_USER]['email'])

    def _check_if_auth_required(self, gateway):
        resp = requests.get("%s/elasticsearch/_cat/indices" % gateway)
        return resp.status_code == 401

    def _get_elastic_access_token(self, username):
        client_secret = self._get_elastic_credential(
            elasticsearch_credential_file,
            credential='keycloak_elasticsearch_client_secret'
        )
        req = requests.post(
            '%s/auth/realms/SF/protocol/'
            'openid-connect/token' % config.GATEWAY_URL,
            data={
                'username': username,
                'password': config.USERS[username]['password'],
                'client_id': 'elasticsearch',
                'grant_type': 'password',
                'client_secret': client_secret,
            }
        )
        try:
            return req.json()['access_token']
        except Exception:
            req.raise_for_status()

    def _get_elastic_credential(self, file_path,
                                credential='elasticsearch_password'):
        if not os.path.exists(file_path):
            return

        with open(file_path, 'r') as f:
            for line in f.readlines():
                # FIXME: Remove after renaming Elasticsearch to Opensearch
                if line.split(':')[0].strip() == credential or \
                        line.split(':')[0].strip() == 'opensearch_password':
                    return line.split(':')[1].strip()

    def _get_ext_elastic_creds(self):
        if not os.path.exists(sfconfig_file):
            return
        with open(sfconfig_file, 'r') as ext_users:
            parsed_file = yaml.safe_load(ext_users)
            if 'external_elasticsearch' in parsed_file:
                return parsed_file['external_elasticsearch']

    def _get_ext_elastic_admin_pass(self, username):
        ext_creds = self._get_ext_elastic_creds()
        if not ext_creds.get('users'):
            return
        for user, creds in ext_creds['users'].items():
            if user == username:
                return creds.get('password')

    def create_request_script_for_logstash(
            self, index, newhash, elastic_url, extra_headers,
            additional_params):
        content = """
curl -s -XPOST '%s/%s/_search?pretty&size=1' %s -d '{
      "query": {
          "bool": {
              "must": [
                  { "match": { "build_name": "config-update" } },
                  { "match": { "build_newrev": "%s" } }
              ]
          }
      }
}' %s
""" % (elastic_url, index, extra_headers, newhash, additional_params)
        return content

    def create_request_script_for_zuul_exporter(
            self, index, newhash, elastic_url, extra_headers,
            additional_params):
        content = """
curl -s -XPOST '%s/%s/_search?pretty&size=1' %s -d '{
      "query": {
          "bool": {
              "must": [
                  { "match": { "job_name": "config-update" } },
                  { "match": { "newrev": "%s" } }
              ]
          }
      }
}' %s
""" % (elastic_url, index, extra_headers, newhash, additional_params)
        return content

    def copy_request_script(self, index, newhash, create_script):
        newhash = newhash.rstrip()
        elastic_url = '%s/elasticsearch' % config.GATEWAY_URL

        if self._get_ext_elastic_creds():
            user = 'admin_sftests_com'
            password = self._get_ext_elastic_admin_pass(user)
        else:
            user = 'admin'
            password = self._get_elastic_credential(
                elasticsearch_credential_file)

        additional_params = ''

        if self._check_if_auth_required(config.GATEWAY_URL):
            if is_present('keycloak') and user == 'admin':
                token = self._get_elastic_access_token(user)
                data = requests.get(
                    elastic_url,
                    headers={
                        'Authorization': 'Bearer %s' % token,
                    }
                ).json()
                additional_params = '-H "Authorization: Bearer %s"' % token
            else:
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, elastic_url, user, password)
                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(handler)
                opener.open(elastic_url)
                urllib.request.install_opener(opener)
                data = json.loads(urllib.request.urlopen(elastic_url).read())
                additional_params = "--user %s:%s" % (user, password)
        else:
            data = json.loads(urllib.request.urlopen(elastic_url).read())

        if data['version']['number'] == '2.4.6':
            extra_headers = " -H 'kbn-version:4.5.4'"
        else:
            extra_headers = " -H 'Content-Type: application/json'"
        content = create_script(
            index, newhash, elastic_url, extra_headers, additional_params)
        with open('/tmp/test_request.sh', 'w') as fd:
            fd.write(content)

    def find_index(self, prefix, include_suffix=True):
        subcmd = ["curl", "-s",
                  "%s/elasticsearch/_cat/indices" % config.GATEWAY_URL]

        # A logstash index is created by day
        today_str = datetime.datetime.utcnow().strftime('%Y.%m.%d')
        index_name = '%s-%s' % (prefix, today_str)

        if self._check_if_auth_required(config.GATEWAY_URL):
            external_elasticsearch = self._get_ext_elastic_creds()
            if external_elasticsearch:
                user = 'admin_sftests_com'
                admin_password = self._get_ext_elastic_admin_pass(user)
                if include_suffix:
                    es_suffix = external_elasticsearch.get('suffix')
                    index_name = '%s-%s-%s' % (prefix, es_suffix, today_str)
                auth_args = [
                    '--user',
                    '%s:%s' % (user, admin_password)
                ]
            else:
                if is_present('keycloak'):
                    token = self._get_elastic_access_token('admin')
                    auth_args = [
                        '-H',
                        'Authorization: Bearer %s' % token
                    ]
                else:
                    user = 'admin'
                    admin_password = self._get_elastic_credential(
                        elasticsearch_credential_file)
                    auth_args = [
                        '--user',
                        '%s:%s' % (user, admin_password)
                    ]

            subcmd += auth_args

        # Here we fetch the index name, but also we wait for
        # it to appears in ElasticSearch for 5 mins
        index = []
        for retry in range(300):
            outlines = subprocess.check_output(
                subcmd).decode("utf-8").split('\n')
            indexes = list(filter(
                lambda l: l.find(index_name) >= 0,
                outlines))
            if indexes:
                break
            time.sleep(1)
        self.assertEqual(
            len(indexes), 1,
            "No %s index has been found for today logstash-%s (%s)" % (
                prefix, today_str, str(indexes)))
        index = indexes[0].split()[2]
        return index

    def verify_logs_exported(self):
        subcmd = ["bash", "/tmp/test_request.sh"]
        for retry in range(300):
            out = subprocess.check_output(subcmd)
            ret = json.loads(out)
            if len(ret['hits']['hits']) >= 1:
                break
            elif len(ret['hits']['hits']) == 0:
                time.sleep(2)
        self.assertEqual(len(ret['hits']['hits']),
                         1,
                         "Fail to find our log in ElasticSeach")
        return ret['hits']['hits'][0]

    def direct_push_in_config_repo(self, url, pname='config'):
        url = url.rstrip('/') + "/%s" % pname
        rand_str = ''.join(random.choice(
            string.ascii_uppercase + string.digits) for _ in range(5))
        clone = self.gitu_admin.clone(url, pname)
        with open('%s/test_%s' % (clone, rand_str), 'w') as fd:
            fd.write('test')
        self.gitu_admin.add_commit_in_branch(
            clone, 'master', ['test_%s' % rand_str])
        head = self.gitu_admin.direct_push_branch(clone, 'master')
        return head

    @skipIfServiceMissing('logscraper')
    @skipIfServiceMissing('logsender')
    def test_zuul_job_console_log_indexation(self):
        """ Test job console logs are exported in Elasticsearch
        """
        head = self.direct_push_in_config_repo(
            'ssh://%s@%s:29418' % (
                config.ADMIN_USER,
                config.GATEWAY_HOST))
        index = self.find_index("logstash")
        self.copy_request_script(
            index, head, self.create_request_script_for_logstash)
        log = self.verify_logs_exported()
        self.assertEqual(log['_source']["build_name"], "config-update")

    @skipIfServiceMissing('elasticsearch')
    def test_zuul_job_indexation(self):
        """ Test job logs are exported in Elasticsearch
        """
        head = self.direct_push_in_config_repo(
            'ssh://%s@%s:29418' % (
                config.ADMIN_USER,
                config.GATEWAY_HOST))
        index = self.find_index("zuul.local")
        self.copy_request_script(
            index, head, self.create_request_script_for_zuul_exporter)
        log = self.verify_logs_exported()
        self.assertEqual(log['_source']["job_name"], "config-update")

    def test_zuul_job_indexation_external_elasticsearch(self):
        """ Test job logs are exported in external Elasticsearch
        """
        if not self._get_ext_elastic_creds():
            return skipReason("There is no configuration set for "
                              "external_elasticsearch. Skipping.")
        head = self.direct_push_in_config_repo(
            'ssh://%s@%s:29418' % (
                config.ADMIN_USER,
                config.GATEWAY_HOST))
        # NOTE: zuul is including the tenant into the
        # index name. More info:
        # https://zuul-ci.org/docs/zuul/reference/drivers/elasticsearch.html
        index = self.find_index("zuul.local", False)
        self.copy_request_script(
            index, head, self.create_request_script_for_zuul_exporter)
        log = self.verify_logs_exported()
        self.assertEqual(log['_source']["job_name"], "config-update")
