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
import random
import string
import subprocess
import time
import urllib.request

from utils import Base, skipIfServiceMissing
from utils import set_private_key
from utils import GerritGitUtils


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

    def copy_request_script(self, index, newhash):
        newhash = newhash.rstrip()
        elastic_url = '%s/elasticsearch' % config.GATEWAY_URL
        try:
            data = json.loads(urllib.request.urlopen(elastic_url).read())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                # FIXME: Change admin credentials when admin password is
                # generated.
                password_mgr.add_password(None, elastic_url, 'admin', 'admin')
                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(handler)
                opener.open(elastic_url)
                urllib.request.install_opener(opener)
                data = json.loads(urllib.request.urlopen(elastic_url).read())

        if data['version']['number'] == '2.4.6':
            extra_headers = " -H 'kbn-version:4.5.4'"
        else:
            extra_headers = " -H 'Content-Type: application/json'"
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
}'
"""
        with open('/tmp/test_request.sh', 'w') as fd:
            fd.write(content % (elastic_url, index, extra_headers, newhash))

    def find_index(self):
        subcmd = ["curl", "-s",
                  "%s/elasticsearch/_cat/indices" % config.GATEWAY_URL]
        # A logstash index is created by day
        today_str = datetime.datetime.utcnow().strftime('%Y.%m.%d')
        # Here we fetch the index name, but also we wait for
        # it to appears in ElasticSearch for 5 mins
        index = []
        for retry in range(300):
            outlines = subprocess.check_output(
                subcmd).decode("utf-8").split('\n')
            indexes = list(filter(
                lambda l: l.find('logstash-%s' % today_str) >= 0,
                outlines))
            if indexes:
                break
            time.sleep(1)
        self.assertEqual(
            len(indexes), 1,
            "No logstash index has been found for today logstash-%s (%s)" % (
                today_str, str(indexes)))
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

    @skipIfServiceMissing('job-logs-gearman-worker')
    def test_log_indexation(self):
        """ Test job log are exported in Elasticsearch
        """
        head = self.direct_push_in_config_repo(
            'ssh://%s@%s:29418' % (
                config.ADMIN_USER,
                config.GATEWAY_HOST))
        index = self.find_index()
        self.copy_request_script(index, head)
        log = self.verify_logs_exported()
        self.assertEqual(log['_source']["build_name"], "config-update")
