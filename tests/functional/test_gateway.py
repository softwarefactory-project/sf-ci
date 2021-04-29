# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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
import json
import urllib.request

from utils import Base
from utils import skipIfServiceMissing
from utils import ManageSfUtils
from utils import skipIfProvisionVersionLesserThan
from utils import GerritClient

from requests.auth import HTTPBasicAuth

import os
import requests
import subprocess

elasticsearch_credential_file = \
        '/var/lib/software-factory/bootstrap-data/secrets.yaml'


class TestGateway(Base):
    def _auth_required(self, url):
        resp = requests.get(url, allow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        self.assertTrue("/auth/login" in resp.headers['Location'])

    def _url_is_not_world_readable(self, url):
        """Utility function to make sure a url is not accessible"""
        resp = requests.get(url)
        self.assertTrue(resp.status_code > 399, resp.status_code)

    def _check_if_auth_required(self, gateway):
        subcmd = ["curl", "-s",
                  "%s/elasticsearch/_cat/indices" % config.GATEWAY_URL]
        return 'Unauthorized' in \
               subprocess.check_output(subcmd).decode("utf-8")

    def _get_elastic_admin_pass(self, file_path):
        if not os.path.exists(file_path):
            return

        with open(file_path, 'r') as f:
            for line in f.readlines():
                if line.split(':')[0].strip() == 'elasticsearch_password':
                    return line.split(':')[1].strip()

    def test_managesf_is_secure(self):
        """Test if managesf config.py file is not world readable"""
        url = "%s/managesf/config.py" % config.GATEWAY_URL
        self._url_is_not_world_readable(url)

    def test_cauth_is_secure(self):
        """Test if managesf config.py file is not world readable"""
        url = "%s/cauth/config.py" % config.GATEWAY_URL
        self._url_is_not_world_readable(url)

    @skipIfProvisionVersionLesserThan("2.4.0")
    def test_dashboard_data(self):
        """ Test if dashboard data are created
        """
        data_url = "%s/dashboards_data/" % config.GATEWAY_URL
        resp = requests.get("%s/data_project_tdpw-project.json" % data_url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("tdpw-info" in resp.text)

    def test_gerrit_accessible(self):
        """ Test if Gerrit is accessible on gateway hosts
        """
        # Unauthenticated calls
        urls = [config.GATEWAY_URL + "/r/",
                config.GATEWAY_URL + "/r/#/"]

        for url in urls:
            resp = requests.get(url)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue('Gerrit Code Review' in resp.text)

        # URL that requires login - fails with Unauthorized
        url = config.GATEWAY_URL + "/r/a/projects/?"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 401)

        # Authenticated URL that requires login
        url = config.GATEWAY_URL + "/r/a/projects/?"
        resp = requests.get(
            url,
            auth=HTTPBasicAuth("user2", config.USERS["user2"]["api_key"]))
        self.assertEqual(resp.status_code, 200)
        # /r/a/projects returns JSON list of projects
        self.assertTrue('All-Users' in resp.text)

    def test_gerrit_projectnames(self):
        """ Test if projectnames similar to LocationMatch settings work
        """
        # Unauthenticated calls, unknown projects. Must return 404, not 30x
        urls = [config.GATEWAY_URL + "/r/dashboard",
                config.GATEWAY_URL + "/r/grafana"]

        for url in urls:
            resp = requests.get(url, allow_redirects=False)
            self.assertEqual(resp.status_code, 404)

    def test_gerrit_api_accessible(self):
        """ Test if Gerrit API is accessible on gateway hosts
        """
        m = ManageSfUtils(config.GATEWAY_URL)
        url = config.GATEWAY_URL + "/r/a/"

        a = GerritClient(url, auth=HTTPBasicAuth("admin", "password"))
        self.assertRaises(RuntimeError, a.get_account, config.USER_1)

        api_passwd = m.create_gerrit_api_password("user3")
        auth = HTTPBasicAuth("user3", api_passwd)
        a = GerritClient(url, auth=auth)
        self.assertTrue(a.get_account("user3"))

        m.delete_gerrit_api_password("user3")
        a = GerritClient(url, auth=auth)
        self.assertRaises(RuntimeError, a.get_account, "user3")

        a = GerritClient(url, auth=HTTPBasicAuth("admin", "password"))
        self.assertRaises(RuntimeError, a.get_account, 'john')

    @skipIfServiceMissing('hound')
    def test_codesearch(self):
        """ Test if codesearch service works
        """
        # Look for 'merge-check', it should returns a zuul.d path
        url = config.GATEWAY_URL + "/codesearch"
        search = "api/v1/search?q=merge-check&repos=*"

        resp = requests.get("%s/%s" % (url, search))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('zuul.d' in resp.text)

    @skipIfServiceMissing('cgit')
    def test_cgit(self):
        """ Test if cgit service works
        """
        # Look for 'config' repository, it should returns a zuul.d path
        url = config.GATEWAY_URL + "/cgit"
        search = "Config repository"

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(search in resp.text)

        # Look for 'zuul' directory in config repository
        url = config.GATEWAY_URL + "/cgit/config/tree/"
        search = "zuul"

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(search in resp.text)

    @skipIfServiceMissing('kibana')
    def test_kibana_accessible(self):
        """ Test if Kibana is accessible on gateway host
        """
        elastic_url = '%s/elasticsearch' % config.GATEWAY_URL
        if self._check_if_auth_required(config.GATEWAY_URL):
            admin_password = self._get_elastic_admin_pass(
                    elasticsearch_credential_file)
            data = json.loads(
                requests.get(elastic_url,
                             auth=HTTPBasicAuth('admin', admin_password)).text)
        else:
            data = json.loads(urllib.request.urlopen(elastic_url).read())

        if data['version']['number'] == '2.4.6':
            url = config.GATEWAY_URL + "/app/kibana"
        else:
            url = config.GATEWAY_URL + "/analytics/app/kibana"

        # Without SSO cookie. Note that auth is no longer enforced

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)

    @skipIfServiceMissing('zuul')
    def test_zuul_accessible(self):
        """ Test if Zuul is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/zuul/"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('Zuul', resp.text)

        url = config.GATEWAY_URL + "/zuul/status"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('Zuul', resp.text)

        # Test api accesss
        url = config.GATEWAY_URL + "/zuul/api/info"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('capabilities', resp.text)

    @skipIfServiceMissing('etherpad')
    def test_etherpad_accessible(self):
        """ Test if Etherpad is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/etherpad/"
        resp = requests.get(
            url,
            cookies=dict(
                auth_pubtkt=config.USERS[config.USER_1]['auth_cookie']))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<title>SF - Etherpad</title>' in resp.text)

    @skipIfServiceMissing('lodgeit')
    def test_paste_accessible(self):
        """ Test if Paste is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/paste/"
        resp = requests.get(
            url,
            cookies=dict(
                auth_pubtkt=config.USERS[config.USER_1]['auth_cookie']))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<title>New Paste | LodgeIt!</title>' in resp.text)

    @skipIfServiceMissing('lodgeit')
    def test_paste_captcha(self):
        """ Test if captcha in Paste service is accessible
        """
        url = config.GATEWAY_URL + "/paste/_captcha.png"
        resp = requests.get(
            url,
            cookies=dict(
                auth_pubtkt=config.USERS[config.USER_1]['auth_cookie']))
        self.assertEqual(resp.status_code, 200)
        # Check if image header "PNG" will be in response
        self.assertTrue('PNG' in resp.text)

    def test_docs_accessible(self):
        """ Test if Sphinx docs are accessible on gateway host
        """
        url = config.GATEWAY_URL + "/docs/index.html"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
