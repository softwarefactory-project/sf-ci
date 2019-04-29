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
import shlex
import urllib

from utils import Base
from utils import skipIfServiceMissing
from utils import services
from utils import ManageSfUtils
from utils import skipIfProvisionVersionLesserThan
from utils import ssh_run_cmd
from utils import GerritClient

from requests.auth import HTTPBasicAuth

import requests


class TestGateway(Base):
    def _auth_required(self, url):
        resp = requests.get(url, allow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        self.assertTrue("/auth/login" in resp.headers['Location'])

    def _url_is_not_world_readable(self, url):
        """Utility function to make sure a url is not accessible"""
        resp = requests.get(url)
        self.assertTrue(resp.status_code > 399, resp.status_code)

    def test_managesf_is_secure(self):
        """Test if managesf config.py file is not world readable"""
        url = "%s/managesf/config.py" % config.GATEWAY_URL
        self._url_is_not_world_readable(url)

    def test_cauth_is_secure(self):
        """Test if managesf config.py file is not world readable"""
        url = "%s/cauth/config.py" % config.GATEWAY_URL
        self._url_is_not_world_readable(url)

    def test_topmenu_links_shown(self):
        """ Test if all service links are shown in topmenu
        """
        subpaths = ["/r/", "/docs/"]
        if "zuul" in services:
            subpaths.append("/zuul/")
        if "etherpad" in services:
            subpaths.append("/etherpad/")
        if "lodgeit" in services:
            subpaths.append("/paste/")
        if "kibana" in services:
            elastic_url = '%s/elasticsearch' % config.GATEWAY_URL
            data = json.loads(urllib.urlopen(elastic_url).read())
            if data['version']['number'] == '2.4.6':
                subpaths.append("/app/kibana")
            else:
                subpaths.append("/analytics")
        if "repoxplorer" in services:
            subpaths.append("/repoxplorer/")
        if "storyboard" in services:
            subpaths.append("/storyboard/")
        url = config.GATEWAY_URL + "/topmenu.html"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        for subpath in subpaths:
            self.assertTrue(('href="%s' % subpath) in resp.text,
                            '%s not present as a link' % subpath)

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
            self.assertTrue('<title>Gerrit Code Review</title>' in resp.text)

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
        # Look for 'config-check', it should returns a zuul.d path
        url = config.GATEWAY_URL + "/codesearch"
        search = "api/v1/search?q=config-check&repos=*"

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
        data = json.loads(urllib.urlopen(elastic_url).read())
        if data['version']['number'] == '2.4.6':
            url = config.GATEWAY_URL + "/app/kibana"
        else:
            url = config.GATEWAY_URL + "/analytics/app/kibana"

        # Without SSO cookie. Note that auth is no longer enforced

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<title>Kibana</title>' in resp.text)

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

    def test_css_js_for_topmenu_accessible(self):
        """ Test if css/js for topmenu are accessible on gateway host
        """
        url = config.GATEWAY_URL + "/static/js/jquery.min.js"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("jQuery" in resp.content)

        paths = ('js/bootstrap.min.js', 'css/bootstrap.min.css')
        for p in paths:
            url = config.GATEWAY_URL + "/static/bootstrap/%s" % p
            resp = requests.get(url)
            self.assertEqual(resp.status_code, 200)

    @skipIfServiceMissing('lodgeit')
    def test_static_dir_for_paste_accessible(self):
        """ Test if static dir for paste is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/static/lodgeit/jquery.js"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("jQuery v1" in resp.content)

    def test_docs_accessible(self):
        """ Test if Sphinx docs are accessible on gateway host
        """
        url = config.GATEWAY_URL + "/docs/index.html"
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_welcome_accessible(self):
        """ Test if Dashboard is accessible on gateway host
        """
        url = config.GATEWAY_URL + "/sf/welcome.html"

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('<body ng-app="sfWelcome"' in resp.text)

    def test_default_redirect(self):
        """ Test if default redirect forwards user to Gerrit
        """
        url = "https://%s/" % config.GATEWAY_HOST
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.url,
                         "https://%s/sf/welcome.html" % config.GATEWAY_HOST)

        self.assertEqual(resp.history[0].status_code, 302)
        self.assertEqual(resp.history[0].url,
                         "https://%s/" % config.GATEWAY_HOST)

    def test_static_files_are_not_cached(self):
        """Make sure files in the 'static' dir are not cached"""
        script = "topmenu.js"
        url = "https://%s/static/js/%s" % (config.GATEWAY_HOST, script)
        js = requests.get(url).text
        # add a comment at the end of the js
        cmd = "echo '// this is a useless comment' >> /var/www/static/js/%s"
        ssh_run_cmd(config.SERVICE_PRIV_KEY_PATH,
                    "root", config.GATEWAY_HOST,
                    shlex.split(cmd % script))
        newjs = requests.get(url).text
        self.assertTrue(len(newjs) > len(js),
                        "New js is %s" % newjs)
        self.assertTrue("useless comment" in newjs,
                        "New js has no useless comment !")