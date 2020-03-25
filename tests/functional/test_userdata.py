# -*- coding: utf-8 -*-
#
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
import requests
import time
import urllib.parse
import warnings
import subprocess

from utils import Base
from utils import ManageSfUtils
from utils import skip
from utils import get_cookie
from utils import get_gerrit_utils
from utils import skipIfServicePresent
from utils import is_present


class TestUserdata(Base):
    @classmethod
    def setUpClass(cls):
        cls.msu = ManageSfUtils(config.GATEWAY_URL)
        cls.gu = get_gerrit_utils("admin")

    def verify_userdata_gerrit(self, login):
        # Now check that the correct data was stored in Gerrit
        data = self.gu.get_account(login)
        self.assertEqual(config.USERS[login]['lastname'], data.get('name'))
        self.assertEqual(config.USERS[login]['email'], data.get('email'))

    def logout(self):
        url = config.GATEWAY_URL + '/auth/logout/'
        requests.get(url)

    def login(self, username, password, redirect='/'):
        url = config.GATEWAY_URL + "/auth/login"
        data = {'username': username,
                'password': password,
                'back': redirect}
        return requests.post(url, data=data)

    def login_kc(self, username, password):
        token_endpoint = "auth/realms/sf/protocol/openid-connect/token"
        url = "%(auth_url)s/%(endpoint)s" % {'auth_url': config.GATEWAY_URL,
                                             'endpoint': token_endpoint}
        resp = requests.post(url, data={'client_id': 'managesf',
                                        'grant_type': 'password',
                                        'username': username,
                                        'password': password})
        return resp

    @skipIfServicePresent("cauth")
    def test_login_kc(self):
        """Verify user creation and ability to log in"""
        username = config.USER_5
        password = config.USERS[config.USER_5]['password']
        resp = self.login_kc(username, password)
        self.assertTrue(resp.ok)
        self.assertTrue('access_token' in resp.json())

    @skipIfServicePresent("keycloak")
    def test_login_and_redirect_cauth(self):
        """ Verify the user creation and the login redirection (cauth)
        """
        self.logout()
        url = config.GATEWAY_URL + "/aservice/"
        quoted_url = urllib.parse.quote(url, safe='')
        response = self.login('user5', config.ADMIN_PASSWORD, quoted_url)

        self.assertEqual(url, response.url)
        self.verify_userdata_gerrit('user5')

    @skipIfServicePresent("keycloak")
    def test_invalid_user_login(self):
        """ Try to login with an invalid user
        """
        self.logout()
        response = self.login('toto', 'nopass', '/')
        self.assertEqual(response.status_code, 401)

    @skipIfServicePresent("keycloak")
    def test_create_local_user_and_login(self):
        """ Try to create a local user then login
        """
        try:
            self.msu.create_user('Flea', 'RHCP', 'flea@slapdabass.com')
        except NotImplementedError:
            skip("user management not supported in this version of managesf")
        self.logout()
        url = config.GATEWAY_URL + "/sf/welcome.html"
        quoted_url = urllib.parse.quote(url, safe='')
        response = self.login('Flea', 'RHCP', quoted_url)
        self.assertEqual(url, response.url)

    @skipIfServicePresent("keycloak")
    def test_delete_user_in_backends_by_username(self):
        """ Delete a user previously registered user by username
        """
        # first, create a user and register it with services
        try:
            self.msu.create_user('bootsy', 'collins', 'funk@mothership.com')
        except NotImplementedError:
            skip("user management not supported in this version of managesf")
        self.logout()
        self.login('bootsy', 'collins', config.GATEWAY_URL)
        # make sure user is in gerrit
        self.assertEqual('funk@mothership.com',
                         self.gu.get_account('bootsy').get('email'))
        # now suppress it
        del_url = config.GATEWAY_URL +\
            '/manage/services_users/?username=bootsy'
        # try with a a non-admin user, it should not work ...
        auth_cookie = get_cookie('user5', config.ADMIN_PASSWORD)
        d = requests.delete(del_url,
                            cookies={'auth_pubtkt': auth_cookie})
        self.assertTrue(400 < int(d.status_code) < 500)
        # try with an admin ...
        auth_cookie = config.USERS[config.ADMIN_USER]['auth_cookie']
        d = requests.delete(del_url,
                            cookies={'auth_pubtkt': auth_cookie})
        self.assertTrue(int(d.status_code) < 400, d.status_code)
        # make sure the user does not exist anymore
        subprocess.Popen([
            "sudo", "env", "EMAIL=funk@mothership.com",
            "/usr/share/sf-config/scripts/delete-gerrit-user.sh",
            "bootsy", "--batch"]).wait()
        time.sleep(1)
        self.assertFalse(self.gu.is_account_active('bootsy'))

    @skipIfServicePresent("keycloak")
    def test_delete_in_backend_and_recreate(self):
        """Make sure we can recreate a user"""
        # first, create a user and register it with services
        try:
            self.msu.create_user('freddie', 'mercury', 'mrbadguy@queen.com')
        except NotImplementedError:
            skip("user management not supported in this version of managesf")
        self.logout()
        self.login('freddie', 'mercury', config.GATEWAY_URL)
        gerrit_id = self.gu.get_account('freddie').get('_account_id')
        del_url = config.GATEWAY_URL +\
            '/manage/services_users/?username=freddie'
        auth_cookie = get_cookie(
            "admin", config.USERS[config.ADMIN_USER]['password'])
        d = requests.delete(del_url,
                            cookies={'auth_pubtkt': auth_cookie})
        self.assertTrue(int(d.status_code) < 400, d.status_code)
        subprocess.Popen([
            "sudo", "env", "EMAIL=mrbadguy@queen.com",
            "/usr/share/sf-config/scripts/delete-gerrit-user.sh",
            "freddie", "--batch"]).wait()
        time.sleep(1)
        self.assertFalse(self.gu.is_account_active('freddie'))
        # recreate the user in the backends
        self.logout()
        self.login('freddie', 'mercury', config.GATEWAY_URL)
        new_gerrit_id = self.gu.get_account('freddie').get('_account_id')
        self.assertTrue(gerrit_id != new_gerrit_id)

    def test_unicode_user(self):
        """ Try to create a local user with unicode charset, login, delete
        """
        auth_cookie = config.USERS[config.ADMIN_USER]['auth_cookie']
        try:
            self.msu.create_user('naruto', 'rasengan', 'datte@bayo.org',
                                 fullname=u'うずまきナルト')
        except NotImplementedError:
            skip("user management not supported in this version of managesf")
        except UnicodeEncodeError:
            # TODO the CLI works but I can't find what is wrong with
            # python's handling of unicode in subprocess.
            warnings.warn('Cannot run shell command with unicode chars for '
                          'whatever reason, retrying with a direct REST '
                          'API call ...',
                          UnicodeWarning)
            create_url = config.GATEWAY_URL + "/manage/user/naruto"
            headers = {'Content-Type': 'application/json; charset=utf8'}
            data = {'email': 'datte@bayo.org',
                    'fullname': 'うずまきナルト',
                    'password': 'rasengan'}
            create_user = requests.post(create_url,
                                        headers=headers,
                                        data=json.dumps(data),
                                        cookies={'auth_pubtkt': auth_cookie})
            self.assertEqual(201,
                             int(create_user.status_code))
        if is_present("cauth"):
            self.logout()
            url = config.GATEWAY_URL + "/sf/welcome.html"
            quoted_url = urllib.parse.quote(url, safe='')
            response = self.login('naruto',
                                  'rasengan', quoted_url)
            self.assertEqual(url, response.url)
        if is_present("keycloak"):
            resp = self.login_kc('naruto', 'rasengan')
            self.assertTrue(resp.ok)
            self.assertTrue('access_token' in resp.json())
        naru_gerrit = self.gu.get_account('naruto')
        self.assertEqual('うずまきナルト',
                         naru_gerrit.get('name'))
        if is_present("cauth"):
            # TODO this should be tested in the tracker as well
            del_url = config.GATEWAY_URL +\
                '/manage/services_users/?username=naruto'
            d = requests.delete(del_url,
                                cookies={'auth_pubtkt': auth_cookie})
            self.assertTrue(int(d.status_code) < 400, d.status_code)
