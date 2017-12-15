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

import os
import config
import shutil
import requests

from utils import Base
from utils import ResourcesUtils
from utils import set_private_key
from utils import GerritGitUtils
from utils import JenkinsUtils
from utils import create_random_str

from pysflib.sfgerrit import GerritUtils


class TestPages(Base):

    def setUp(self):
        super(TestPages, self).setUp()
        self.projects = []
        self.dirs_to_delete = []
        self.ru = ResourcesUtils()
        # To interact with created repo(s)
        priv_key_path = set_private_key(
            config.USERS[config.ADMIN_USER]["privkey"])
        self.gitu_admin = GerritGitUtils(
            config.ADMIN_USER,
            priv_key_path,
            config.USERS[config.ADMIN_USER]['email'])
        self.gu = GerritUtils(
            config.GATEWAY_URL,
            auth_cookie=config.USERS[config.ADMIN_USER]['auth_cookie'])
        self.ju = JenkinsUtils()

    def tearDown(self):
        for dirs in self.dirs_to_delete:
            shutil.rmtree(dirs)

    def create_project(self, name):
        self.ru.create_repo(name)
        self.projects.append(name)

    def clone_as_admin(self, pname):
        url = "ssh://%s@%s:29418/%s" % (config.ADMIN_USER,
                                        config.GATEWAY_HOST,
                                        pname)
        clone_dir = self.gitu_admin.clone(url, pname)
        if os.path.dirname(clone_dir) not in self.dirs_to_delete:
            self.dirs_to_delete.append(os.path.dirname(clone_dir))
        return clone_dir

    def commit_direct_push_as_admin(self, clone_dir, msg):
        # Stage, commit and direct push the additions on master
        self.gitu_admin.add_commit_for_all_new_additions(clone_dir, msg)
        return self.gitu_admin.direct_push_branch(clone_dir, 'master')

    def test_pages(self):
        """ Test sf-pages publication - raw content
        """
        # Create project
        pname = create_random_str()
        self.create_project(pname)

        # Register it in zuul
        config_dir = self.clone_as_admin("config")
        tenant = os.path.join(config_dir, "zuulV3", pname + ".yaml")
        job = os.path.join(config_dir, "zuul.d", pname + ".yaml")
        file(tenant, 'w').write("""---
- tenant:
    name: 'local'
    source:
      gerrit:
        untrusted-projects:
          - %s
""" % pname)
        file(job, 'w').write("""---
- job:
    name: %(pname)s-build-and-publish-website
    parent: build-and-publish-pages
    vars:
      vhost_name: %(pname)s
    final: true
    allowed-projects:
      - %(pname)s
""" % {'pname': pname})
        change_sha = self.commit_direct_push_as_admin(
            config_dir, "Set website job")
        config_update_result = self.ju.wait_for_config_update(
            change_sha, return_result=True)
        self.assertEqual(config_update_result, 'SUCCESS')

        # Add raw content and define .zuul.yaml
        clone_dir = self.clone_as_admin(pname)
        path = os.path.join(clone_dir, "index.html")
        zuul = os.path.join(clone_dir, ".zuul.yaml")
        file(path, 'w').write("<b>Hello World !</b>")
        file(zuul, 'w').write("""---
- project:
    name: %s
    check:
      jobs:
        - %s-build-and-publish-website
""" % (pname, pname))
        # We run the publication in the check pipeline
        # to speed up the test, should be done in the gate
        # in the real life
        change_sha = self.gitu_admin.add_commit_and_publish(
            clone_dir, "master", "Test change",
            fnames=['.zuul.yaml', 'index.html'])
        change_nr = self.gu.get_change_number(change_sha)
        note = self.gu.wait_for_verify(
            change_nr, ['zuul'], timeout=240)
        self.assertEqual(note, 1)

        # Now attempt to access the published content
        resp = requests.get(
            "http://%s" % config.GATEWAY_HOST,
            headers={'Host': "%s.%s" % (pname, config.GATEWAY_HOST)})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, '<b>Hello World !</b>')
