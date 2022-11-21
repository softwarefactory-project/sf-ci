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
import requests

from utils import Base


class TestKeycloak(Base):

    def login(self, username, password):
        token_endpoint = "auth/realms/sf/protocol/openid-connect/token"
        url = "%(auth_url)s/%(endpoint)s" % {'auth_url': config.GATEWAY_URL,
                                             'endpoint': token_endpoint}
        resp = requests.post(url, data={'client_id': 'managesf',
                                        'grant_type': 'password',
                                        'username': username,
                                        'password': password})
        return resp

    def test_login(self):
        """Verify user creation and ability to log in"""
        username = config.USER_5
        password = config.USERS[config.USER_5]['password']
        resp = self.login(username, password)
        self.assertTrue(resp.ok)
        self.assertTrue('access_token' in resp.json())
