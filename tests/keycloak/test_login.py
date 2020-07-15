#!/bin/env python
#
# Copyright (C) 2020 Red Hat
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

import os
import time
import unittest

from selenium import webdriver
from selenium.webdriver.firefox.options import Options


class LoginTest(unittest.TestCase):
    def setUp(self):
        options = Options()
        # options.headless = True
        self.driver = webdriver.Firefox(
            executable_path='/usr/local/bin/geckodriver',
            options=options)

    def tearDown(self):
        self.driver.close()

    def test_user_login(self):
        self.driver.get('http://localhost:8080/auth/realms/test/account')
        self.driver.find_element_by_name("username").send_keys('testuser')
        pwd = self.driver.find_element_by_name("password")
        pwd.send_keys('testpassword')
        pwd.submit()
        time.sleep(5)
        user_details_title = '<title>Keycloak Account Management</title>'
        self.assertTrue(user_details_title in self.driver.page_source,
                        self.driver.page_source)

    def test_github_login(self):
        gh_login = os.getenv('GH_USER')
        gh_pass = os.getenv('GH_PASSWORD')
        self.driver.get('http://localhost:8080/auth/realms/test/account')
        self.driver.find_element_by_id('zocial-github').click()
        # wait for github login page to load
        time.sleep(5)
        self.driver.find_element_by_id('login_field').send_keys(gh_login)
        pwd = self.driver.find_element_by_name("password")
        pwd.send_keys(gh_pass)
        pwd.submit()
        # wait for the authorization screen if necessary
        time.sleep(5)
        authorize = self.driver.find_element_by_id('js-oauth-authorize-btn')
        if authorize:
            authorize.click()
            time.sleep(5)
        # User info update form
        self.driver.find_element_by_id('firstName').send_keys('GitHub')
        self.driver.find_element_by_id('lastName').send_keys('TestAccount')
        self.driver.find_element_by_id('lastName').submit()
        time.sleep(5)
        user_details_title = '<title>Keycloak Account Management</title>'
        self.assertTrue(user_details_title in self.driver.page_source,
                        self.driver.page_source)
