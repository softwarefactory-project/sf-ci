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
        self.driver.get('https://mhusftest.org/auth/realms/SF/account')
        self.driver.find_element_by_name("username").send_keys('testuser')
        self.driver.find_element_by_name("password").send_keys('testpassword')
        self.driver.find_element_by_name("password").submit()
        time.sleep(5)
        user_details_title = '<title>Keycloak Account Management</title>'
        self.assertTrue(user_details_title in self.driver.page_source,
                        self.driver.page_source)
