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
import random
import yaml
import subprocess

import config
import logging

from utils import ManageSfUtils
from utils import ResourcesUtils
from utils import GerritGitUtils
from utils import get_auth_params
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
        if not config.KC_AUTH:
            auth = get_auth_params(
                config.ADMIN_USER, config.USERS[config.ADMIN_USER]['password'])
            cookie = auth['cookies']['auth_pubtkt']
            config.USERS[config.ADMIN_USER]['auth_cookie'] = cookie
        self.msu = ManageSfUtils(config.GATEWAY_URL)
        self.ru = ResourcesUtils()
        self.ggu = GerritGitUtils(config.ADMIN_USER,
                                  config.ADMIN_PRIV_KEY_PATH,
                                  config.USERS[config.ADMIN_USER]['email'])

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

    def create_issues_on_project(self, name, issues):
        self.log.info(" Create %s issue(s) for that project ..." % len(issues))
        for i in issues:
            issue = (random.randint(1, 100), random.randint(1, 100))
            yield issue, i['review']

    def simple_login(self, user, password):
        """log as user to make the user listable"""
        try:
            params = get_auth_params(user, password)
            if params['cookies'] == params['headers'] == {}:
                raise Exception('no auth')
        except Exception:
            self.log.error("Couldn't log in as %s" % user)
            exit(1)

    def create_review(self, project, commit_message, branch='master'):
        """Very basic review creator for statistics and restore tests
        purposes."""
        self.ggu.config_review(self.clone_dir)
        self.ggu.add_commit_in_branch(
            self.clone_dir,
            branch,
            commit=commit_message)
        self.ggu.review_push_branch(self.clone_dir, branch)

    def create_review_for_issue(self, project, issue):
        self.create_review(project, 'test\n\nTask: #%s\nStory: #%s' % (
                           issue[0], issue[1]), 'branch_%s' % str(issue[0]))

    def create_local_user(self, username, password, email):
        self.msu.create_user(username, password, email)

    def command(self, cmd):
        return subprocess.check_output(cmd, shell=True)

    def compute_checksum(self, f):
        out = self.command("md5sum %s" % f)
        if out:
            return out.split()[0]

    def read_file(self, f):
        return open(f).read()

    def provision(self):
        for cmd in self.resources['commands']:
            self.log.info("Execute command %s" % cmd['cmd'])
            out = self.command(cmd['cmd'])
            if out:
                self.log.info(out)
        checksum_list = {}
        for checksum in self.resources['checksum']:
            self.log.info("Compute checksum for file %s" % checksum['file'])
            checksum_list[checksum['file']] = self.compute_checksum(
                checksum['file'])
            checksum_list['content_' + checksum['file']] = self.read_file(
                checksum['file'])
        yaml.dump(checksum_list, open('pc_checksums.yaml', 'w'),
                  default_flow_style=False)
        for user in self.resources['local_users']:
            self.log.info("Create local user %s" % user['username'])
            self.create_local_user(user['username'],
                                   user['password'],
                                   user['email'])
            if not is_present("keycloak"):
                self.simple_login(user['username'], user['password'])
                self.log.info("log in as %s" % user['username'])
        for u in self.resources['users']:
            if not is_present("keycloak"):
                self.log.info("log in as %s" % u['name'])
                self.simple_login(u['name'],
                                  config.USERS[u['name']]['password'])
        for project in self.resources['projects']:
            self.log.info("Create user datas for %s" % project['name'])
            self.create_project(project['name'])
            self.push_files_in_project(project['name'],
                                       [f['name'] for f in project['files']])
            for i, review in self.create_issues_on_project(project['name'],
                                                           project['issues']):
                if review:
                    self.log.info("Create review for bug %s in %s" %
                                  (i, project['name']))
                    self.create_review_for_issue(project['name'], i)

        self.create_resources()


p = SFProvisioner()
p.provision()
