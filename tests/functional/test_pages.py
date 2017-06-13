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
import time
import config
import shutil
import requests

from utils import Base
from utils import ResourcesUtils
from utils import set_private_key
from utils import GerritGitUtils
from utils import create_random_str
from utils import skipIfServiceMissing


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

    def tearDown(self):
        for name in self.projects:
            self.ru.delete_repo(name)
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

    @skipIfServiceMissing('pages')
    def test_pages(self):
        """ Test sf-pages publication - raw content
        """
        # This test verify raw content is published and accessible
        pname = "%s.%s" % (create_random_str(), config.GATEWAY_HOST)
        self.create_project(pname)
        clone_dir = self.clone_as_admin(pname)
        path = os.path.join(clone_dir, "index.html")
        file(path, 'w').write("<b>Hello World !</b>")
        self.commit_direct_push_as_admin(clone_dir, "Update website")
        c = 0
        while True:
            if c >= 90:
                raise Exception("Unable to find the publication")
            resp = requests.get("http://%s" % config.GATEWAY_HOST,
                                headers={'Host': pname})
            if resp.status_code == 200:
                content = resp.text
                self.assertEqual(content, '<b>Hello World !</b>')
                break
            else:
                time.sleep(1)
                c += 1
