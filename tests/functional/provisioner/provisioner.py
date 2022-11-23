#!/bin/env python3
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

import os
import yaml

import config
import logging

from utils import ResourcesUtils
from utils import GerritGitUtils
from utils import KeycloakUtils
from utils import get_gerrit_utils
from utils import is_present


# TODO: Create pads and pasties.


class SFProvisioner(object):
    """ This provider is only intended for testing
    SF backup/restore and update. It provisions some
    user datas in a SF installation based on a resourses.yaml
    file. Later those data can be checked by its friend
    the SFChecker.

    Provisioned data should remain really simple.
    """
    log = logging.getLogger("Provisioner")

    def __init__(self):
        with open("%s/resources.yaml" % os.getcwd(), 'r') as rsc:
            self.resources = yaml.load(rsc)
        self.ru = ResourcesUtils()
        self.ku = KeycloakUtils(config.GATEWAY_URL)
        self.ggu = GerritGitUtils(config.ADMIN_USER,
                                  config.ADMIN_PRIV_KEY_PATH,
                                  config.USERS[config.ADMIN_USER]['email'])
        self.gerrit_admin_client = get_gerrit_utils("admin")

    def create_resources(self):
        self.ru.create_resources("provisioner",
                                 {'resources': self.resources['resources']})
        # Create review for the first few repositories
        for project in list(self.resources['resources']['repos'].keys())[:3]:
            self.clone_project(project)
            self.create_review(project, "Test review for %s" % project)

    def create_project(self, name):
        self.log.info(" Creating project %s ..." % name)
        self.ru.create_repo(name)

    def clone_project(self, name):
        # TODO(fbo); use gateway host instead of gerrit host
        self.url = "ssh://%s@%s:29418/%s" % (config.ADMIN_USER,
                                             config.GATEWAY_HOST, name)
        self.clone_dir = self.ggu.clone(self.url, name, config_review=False)

    def push_files_in_project(self, name, files):
        self.log.info(" Add files(%s) in a commit ..." % ",".join(files))
        self.clone_project(name)
        for f in files:
            open(os.path.join(self.clone_dir, f), 'w').write('data')
            self.ggu.git_add(self.clone_dir, (f,))
        self.ggu.add_commit_for_all_new_additions(self.clone_dir)
        self.ggu.direct_push_branch(self.clone_dir, 'master')

    def create_review(self, project, commit_message, branch='master'):
        """Very basic review creator for statistics and restore tests
        purposes."""
        self.ggu.config_review(self.clone_dir)
        self.ggu.add_commit_in_branch(
            self.clone_dir,
            branch,
            commit=commit_message)
        self.ggu.review_push_branch(self.clone_dir, branch)

    def create_local_user(self, username, password, email):
        if is_present("keycloak"):
            self.ku.create_user(username, password, email)
        self.gerrit_admin_client.create_account(username, password, email)

    def provision(self):
        for user in self.resources['local_users']:
            self.log.info("Create local user %s" % user['username'])
            self.create_local_user(user['username'],
                                   user['password'],
                                   user['email'])
        for project in self.resources['projects']:
            self.log.info("Create project %s" % project['name'])
            self.create_project(project['name'])
            self.push_files_in_project(project['name'],
                                       [f['name'] for f in project['files']])
        self.create_resources()


p = SFProvisioner()
p.provision()
