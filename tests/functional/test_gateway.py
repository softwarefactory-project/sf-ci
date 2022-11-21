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
import yaml

from utils import Base
from utils import skipIfServiceMissing
from utils import skipReason
from utils import skipIfProvisionVersionLesserThan
from utils import skipIf
from utils import GerritClient
from utils import is_present

from requests.auth import HTTPBasicAuth

import os
import requests

bootstrap_dir = '/var/lib/software-factory/bootstrap-data'
opensearch_credential_file = '%s/secrets.yaml' % bootstrap_dir
sfconfig_file = '/etc/software-factory/sfconfig.yaml'


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
        resp = requests.get("%s/opensearch/_cat/indices" % gateway)
        # NOTE: Remove condition below when SF 3.8 released.
        if resp.status_code == 404:
            resp = requests.get("%s/elasticsearch/_cat/indices" % gateway)
        return resp.status_code == 401

    def _get_opensearch_admin_pass(self, file_path):
        if not os.path.exists(file_path):
            return

        with open(file_path, 'r') as f:
            for line in f.readlines():
                # NOTE: Change condition below when SF 3.8 released.
                if (line.split(':')[0].strip() == 'opensearch_password' or
                        line.split(':')[0].strip(
                        ) == 'elasticsearch_password'):
                    return line.split(':')[1].strip()

    def _get_ext_opensearch_creds(self):
        if not os.path.exists(sfconfig_file):
            return
        with open(sfconfig_file, 'r') as ext_users:
            parsed_file = yaml.safe_load(ext_users)
            if 'external_opensearch' in parsed_file:
                return parsed_file['external_opensearch']
            # NOTE: Remove condition below when SF 3.8 released.
            if 'external_elasticsearch' in parsed_file:
                return parsed_file['external_elasticsearch']

    def _get_ext_opensearch_admin_pass(self, username):
        ext_creds = self._get_ext_opensearch_creds()
        if not ext_creds.get('users'):
            return
        for user, creds in ext_creds['users'].items():
            if user == username:
                return creds.get('password')

    def _is_kibana_external(self, file_path):
        with open(file_path, 'r') as sf_config:
            parsed_file = yaml.safe_load(sf_config)
            return parsed_file.get('kibana', {}).get('host_url')

    def _determine_elasticsearch_url(self, gateway):
        opensearch_url = '%s/opensearch' % gateway
        r = requests.get(opensearch_url)
        if r.status_code != 404:
            return opensearch_url
        return '%s/elasticsearch' % gateway

    def test_managesf_is_secure(self):
        """Test if managesf config.py file is not world readable"""
        url = "%s/managesf/config.py" % config.GATEWAY_URL
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
            auth=HTTPBasicAuth("user2", config.USERS["user2"]["password"]))
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

    def test_gerrit_api_accessible_keycloak(self):
        """ Test if Gerrit API is accessible on gateway hosts (SSO: keycloak)
        """
        url = config.GATEWAY_URL + "/r/a/"

        a = GerritClient(url, auth=HTTPBasicAuth("admin", "password"))
        self.assertRaises(RuntimeError, a.get_account, config.USER_1)

        auth = HTTPBasicAuth("user3", config.USERS["user3"]["password"])
        a = GerritClient(url, auth=auth)
        self.assertTrue(a.get_account("user3"))

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

    @skipIfServiceMissing('opensearch-dashboards')
    def test_kibana_accessible(self):
        """ Test if Kibana is accessible on gateway host
        """
        if self._is_kibana_external(sfconfig_file):
            return skipReason("Skipping test due external Kibana host is "
                              "configured")

        url = self._determine_elasticsearch_url(config.GATEWAY_URL)
        if self._check_if_auth_required(config.GATEWAY_URL):
            admin_password = self._get_opensearch_admin_pass(
                opensearch_credential_file)
            data = json.loads(
                requests.get(url,
                             auth=HTTPBasicAuth('admin', admin_password)
                             ).text)
        else:
            data = json.loads(urllib.request.urlopen(url).read())

        if data['version']['number'] == '2.4.6':
            url = config.GATEWAY_URL + "/app/kibana"
        else:
            url = config.GATEWAY_URL + "/analytics/app/kibana"

        # Without SSO cookie. Note that auth is no longer enforced
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_kibana_accessible_ext_host(self):
        """ Test if Kibana on external host is accessible on gateway host
        """
        if not self._is_kibana_external(sfconfig_file):
            return skipReason("Skipping test due external Kibana host is not "
                              "configured")
        url = self._determine_elasticsearch_url(config.GATEWAY_URL)
        verify = True
        if self._check_if_auth_required(config.GATEWAY_URL):
            user = 'admin'
            if self._get_ext_opensearch_creds():
                user = 'admin_sftests_com'
                admin_password = self._get_ext_opensearch_admin_pass(user)
                verify = False
            else:
                admin_password = self._get_opensearch_admin_pass(
                        opensearch_credential_file)

            data = json.loads(
                requests.get(url,
                             auth=HTTPBasicAuth(user, admin_password),
                             verify=verify).text)
        else:
            data = json.loads(urllib.request.urlopen(url).read())

        if data['version']['number'] == '2.4.6':
            url = config.GATEWAY_URL + "/app/kibana"
        else:
            url = config.GATEWAY_URL + "/analytics/app/kibana"

        # Without SSO cookie. Note that auth is no longer enforced
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_kibana_without_autologin(self):
        """ Test if kibana user can not be automatically logged to Kibana
        """
        if (not self._is_kibana_external(sfconfig_file) and
                not is_present('kibana')):
            return skipReason("Skipping test due Kibana is not configured")

        url = config.GATEWAY_URL + "/analytics/app/kibana"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        # if keycloak is used, there is an extra redirection.
        self.assertTrue(
            'nextUrl' in resp.url
            or 'nextUrl' in resp.history[-1].url)

    def test_kibana_autologin(self):
        """ Test if kibana user can be automatically logged to Kibana
        """
        if (not self._is_kibana_external(sfconfig_file) and
                not is_present('kibana')):
            return skipReason("Skipping test due Kibana is not configured")

        url = config.GATEWAY_URL + "/analytics_autologin/app/kibana_overview"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse('nextUrl' in resp.url)

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

    @skipIfServiceMissing('zuul')
    @skipIf(
        config.groupvars['zuul'].get('external_authenticators', []) == [],
        'No external authenticator set'
    )
    def test_zuul_third_party_authenticator(self):
        """ Test if Zuul authenticators are correctly set
        """
        url = config.GATEWAY_URL + "/zuul/api/info"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        zuul_info = resp.json()
        self.assertTrue('info' in zuul_info, zuul_info)
        self.assertTrue('capabilities' in zuul_info['info'], zuul_info)
        self.assertTrue('auth' in zuul_info['info']['capabilities'],
                        zuul_info)
        zuul_auth = zuul_info['info']['capabilities']['auth']
        self.assertTrue('realms' in zuul_auth, zuul_info)
        self.assertTrue('dummy_sso' in zuul_auth['realms'], zuul_info)
        for k, v in [
            ('authority', 'https://keycloak/auth/realms/dummy'),
            ('client_id', 'zuul_dummy'),
            ('driver', 'OpenIDConnect'),
        ]:
            self.assertEqual(
                v,
                zuul_auth['realms']['dummy_sso'][k],
                zuul_auth
            )

    @skipIfServiceMissing('etherpad')
    def test_etherpad_accessible(self):
        """ Test if Etherpad is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/etherpad/"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<title>SF - Etherpad</title>' in resp.text)

    @skipIfServiceMissing('lodgeit')
    def test_paste_accessible(self):
        """ Test if Paste is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/paste/"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<title>New Paste | LodgeIt!</title>' in resp.text)

    @skipIfServiceMissing('lodgeit')
    def test_paste_captcha(self):
        """ Test if captcha in Paste service is accessible
        """
        url = config.GATEWAY_URL + "/paste/_captcha.png"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        # Check if image header "PNG" will be in response
        self.assertTrue('PNG' in resp.text)

    def test_docs_accessible(self):
        """ Test if Sphinx docs are accessible on gateway host
        """
        url = config.GATEWAY_URL + "/docs/index.html"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
