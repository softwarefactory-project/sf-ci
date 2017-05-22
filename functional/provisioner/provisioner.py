#!/bin/env python
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
import shlex
import random
import sys
import yaml

pwd = os.path.dirname(os.path.abspath(__file__))  # flake8: noqa
sys.path.append(os.path.dirname(pwd))             # flake8: noqa
import config

from utils import ManageSfUtils
from utils import GerritGitUtils
from pysflib.sfredmine import RedmineUtils
from utils import JenkinsUtils
from utils import get_cookie
from utils import is_present
from utils import ssh_run_cmd

# TODO: Create pads and pasties.


class SFProvisioner(object):
    """ This provider is only intended for testing
    SF backup/restore and update. It provisions some
    user datas in a SF installation based on a resourses.yaml
    file. Later those data can be checked by its friend
    the SFChecker.

    Provisioned data should remain really simple.
    """
    def __init__(self):
        with open("%s/resources.yaml" % pwd, 'r') as rsc:
            self.resources = yaml.load(rsc)
        config.USERS[config.ADMIN_USER]['auth_cookie'] = get_cookie(
            config.ADMIN_USER, config.USERS[config.ADMIN_USER]['password'])
        self.msu = ManageSfUtils(config.GATEWAY_URL)
        self.ggu = GerritGitUtils(config.ADMIN_USER,
                                  config.ADMIN_PRIV_KEY_PATH,
                                  config.USERS[config.ADMIN_USER]['email'])
        self.ju = JenkinsUtils()
        self.rm = RedmineUtils(
            config.GATEWAY_URL + "/redmine/",
            auth_cookie=config.USERS[config.ADMIN_USER]['auth_cookie'])

    def create_project(self, name):
        print " Creating project %s ..." % name
        self.msu.createProject(name, config.ADMIN_USER)

    def push_files_in_project(self, name, files):
        print " Add files(%s) in a commit ..." % ",".join(files)
        # TODO(fbo); use gateway host instead of gerrit host
        self.url = "ssh://%s@%s:29418/%s" % (config.ADMIN_USER,
                                             config.GATEWAY_HOST, name)
        clone_dir = self.ggu.clone(self.url, name, config_review=False)
        self.clone_dir = clone_dir
        for f in files:
            file(os.path.join(clone_dir, f), 'w').write('data')
            self.ggu.git_add(clone_dir, (f,))
        self.ggu.add_commit_for_all_new_additions(clone_dir)
        self.ggu.direct_push_branch(clone_dir, 'master')

    def create_issues_on_project(self, name, issues):
        print " Create %s issue(s) for that project ..." % len(issues)
        for i in issues:
            if is_present('SFRedmine'):
                issue = self.rm.create_issue(name, i['name'])
            else:
                issue = random.randint(1,100)
            yield issue, i['review']

    def create_jenkins_jobs(self, name, jobnames):
        print " Create Jenkins jobs(%s)  ..." % ",".join(jobnames)
        for jobname in jobnames:
            self.ju.create_job("%s_%s" % (name, jobname))

    def create_pads(self, amount):
        # TODO
        pass

    def create_pasties(self, amount):
        # TODO
        pass


    def simple_login(self, user):
        """log as user to make the user listable"""
        get_cookie(user, config.USERS[user]['password'])


    def create_review(self, project, issue):
        """Very basic review creator for statistics and restore tests
        purposes."""
        self.ggu.config_review(self.clone_dir)
        self.ggu.add_commit_in_branch(self.clone_dir,
                                      'branch_' + issue,
                                      commit='test\n\nBug: %s' % issue)
        self.ggu.review_push_branch(self.clone_dir, 'branch_' + issue)

    def create_local_user(self, username, password, email):
        self.msu.create_user(username, password, email)

    def command(self, cmd):
        return ssh_run_cmd(os.path.expanduser("~/.ssh/id_rsa"),
                           "root",
                           config.GATEWAY_HOST, shlex.split(cmd))

    def compute_checksum(self, f):
        out = self.command("md5sum %s" % f)[0]
        if out:
            return out.split()[0]

    def provision(self):
        for cmd in self.resources['commands']:
            print "Execute command %s" % cmd['cmd']
            print self.command(cmd['cmd'])
        checksum_list = {}
        for checksum in self.resources['checksum'] :
            print "Compute checksum for file %s" % checksum['file']
            checksum_list[checksum['file']] = self.compute_checksum(
                checksum['file'])
        yaml.dump(checksum_list, file('/tmp/pc_checksums.yaml', 'w'))
        for user in self.resources['local_users']:
            print "Create local user %s" % user['username']
            self.create_local_user(user['username'],
                                   user['password'],
                                   user['email'])
        for u in self.resources['users']:
            print "log in as %s" % u['name']
            self.simple_login(u['name'])
        for project in self.resources['projects']:
            print "Create user datas for %s" % project['name']
            self.create_project(project['name'])
            self.push_files_in_project(project['name'],
                                       [f['name'] for f in project['files']])
            for i, review in self.create_issues_on_project(project['name'],
                                                           project['issues']):
                if review:
                    print "Create review for bug %i in %s" % (i,
                                                              project['name'])
                    self.create_review(project['name'], str(i))
            self.create_jenkins_jobs(project['name'],
                                     [j['name'] for j in project['jobnames']])
        self.create_pads(2)
        self.create_pasties(2)

p = SFProvisioner()
p.provision()
