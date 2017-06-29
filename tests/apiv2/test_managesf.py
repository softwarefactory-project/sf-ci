# Copyright (C) 2017 Red Hat
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


from tests.functional import config, utils

import requests

import os


class TestManageSFAPIv2(utils.Base):
    """This test is intended to be run after the zuul health check,
    to query data about the previous builds."""
    def setUp(self):
        super(TestManageSFAPIv2, self).setUp()
        self.admin_cookie = dict(
            auth_pubtkt=config.USERS[config.ADMIN_USER]['auth_cookie'])
        self.base_url = config.MANAGESF_API + "api/v2/"
        self.project = os.getenv('HEALTHCHECK_PROJECT')
        if self.project is None:
            raise Exception(
                "This test must be run after the zuul health-check playbook, "
                "and env variable $HEALTHCHECK_PROJECT must be set "
                "accordingly")
        self.pipelines = {"check": ["health-%s-unit-tests" % self.project, ],
                          "gate": ["health-%s-unit-tests" % self.project,
                                   "health-%s-functional-tests" % self.project,
                                   ]
                          }

    def test_get_builds(self):
        url = self.base_url + "builds/"
        resp = requests.get(url, cookies=self.admin_cookie)
        self.assertTrue(resp.status_int < 400, resp.status_int)

    def test_get_buildsets(self):
        url = self.base_url + "buildsets/"
        resp = requests.get(url, cookies=self.admin_cookie)
        self.assertTrue(resp.status_int < 400, resp.status_int)

    def test_get_jobs(self):
        url = self.base_url + "jobs/"
        resp = requests.get(url, cookies=self.admin_cookie)
        self.assertTrue(resp.status_int < 400, resp.status_int)
