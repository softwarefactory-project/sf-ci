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
import requests
import sys
import yaml
from bs4 import BeautifulSoup
import subprocess

import config

from utils import get_cookie
from utils import get_gerrit_utils
from utils import GerritGitUtils


class SFchecker:
    """ This checker is only intended for testin
    SF backup/restore and update. It checks that the user
    data defined in resourses.yaml are present on the SF.

    Those data must have been provisioned by SFProvisioner.
    """
    def __init__(self):
        with open("%s/resources.yaml" % os.getcwd(), 'r') as rsc:
            self.resources = yaml.load(rsc)
        config.USERS[config.ADMIN_USER]['auth_cookie'] = get_cookie(
            config.ADMIN_USER, config.USERS[config.ADMIN_USER]['password'])
        self.gu = get_gerrit_utils("admin")
        self.ggu = GerritGitUtils(config.ADMIN_USER,
                                  config.ADMIN_PRIV_KEY_PATH,
                                  config.USERS[config.ADMIN_USER]['email'])

    def check_project(self, name):
        print(" Check project %s exists ..." % name, end='')
        if not self.gu.project_exists(name):
            print("FAIL")
            exit(1)
        print("OK")

    def check_files_in_project(self, name, files):
        print(" Check files(%s) exists in project ..." % ",".join(files),
              end='')
        # TODO(fbo); use gateway host instead of gerrit host
        url = "ssh://%s@%s:29418/%s" % (config.ADMIN_USER,
                                        config.GATEWAY_HOST, name)
        clone_dir = self.ggu.clone(url, name, config_review=False)
        for f in files:
            if not os.path.isfile(os.path.join(clone_dir, f)):
                print("FAIL")
                exit(1)

    def check_reviews_on_project(self, name, issues):
        reviews = [i for i in issues if i['review']]
        print(" Check that at least %s reviews exists for that project ..." %
              len(reviews), end='')
        pending_reviews = self.ggu.list_open_reviews(name, config.GATEWAY_HOST)
        if not len(pending_reviews) >= len(reviews):
            print("FAIL")
            exit(1)
        print("OK")

    def command(self, cmd):
        return subprocess.check_output(cmd, shell=True)

    def compute_checksum(self, f):
        out = self.command("md5sum %s" % f)
        if out:
            return out.split()[0]

    def read_file(self, f):
        return open(f).read()

    def simple_login(self, user, password):
        """log as user"""
        return get_cookie(user, password)

    def check_users_list(self):
        print("Check that users are listable ...", end='')
        users = [u['name'] for u in self.resources['users']]
        c = {'auth_pubtkt': config.USERS[config.ADMIN_USER]['auth_cookie']}
        url = 'http://%s/manage/services_users/' % config.GATEWAY_HOST
        registered = requests.get(url,
                                  cookies=c).json()
        # usernames are in first position
        r_users = [u['username'] for u in registered]
        if not set(users).issubset(set(r_users)):
            print("FAIL: expected %s, got %s" % (users, r_users))
            exit(1)
        print("OK")

    def check_credentials(self, new_creds, old_creds):
        new = BeautifulSoup(new_creds, 'lxml')
        old = BeautifulSoup(old_creds, 'lxml')
        return set(n.string for n in new.find_all('id')) !=\
            set(o.string for o in old.find_all('id'))

    def check_checksums(self):
        print("Check that expected file are there")
        checksum_list = yaml.load(open('pc_checksums.yaml'))
        mismatch = False
        for f, checksum in checksum_list.items():
            if f.startswith("content_"):
                continue
            # SF service user password is regenerated after sfconfig
            # so the checksums will not match. Instead, make sure ids are
            # still there.
            if f.endswith("credentials.xml"):
                old_file = checksum_list['content_' + f]
                mismatch = self.check_credentials(self.read_file(f),
                                                  old_file)
                if not mismatch:
                    print("Jenkins credentials file is OK.")
                else:
                    print("Jenkins credentials mismatch:\n")
                    print("New file is:")
                    print("    %s" % self.read_file(f).replace("\n", "\n    "))
                    print("Old file was:")
                    print("    %s" % old_file.replace("\n", "\n    "))
                continue
            c = self.compute_checksum(f)
            if c == checksum:
                print("Expected checksum (%s) for %s is OK." % (
                    checksum, f))
            else:
                print("Expected checksum (%s) for %s is WRONG (%s)." % (
                    checksum, f, c))
                print("New file is:")
                print("    %s" % self.read_file(f).replace("\n", "\n    "))
                print("Old file was:")
                print("    %s" % checksum_list['content_' + f].replace(
                    "\n", "\n    "))
                mismatch = True
        if "checksum_warn_only" not in sys.argv and mismatch:
            sys.exit(1)

    def checker(self):
        self.check_checksums()
        self.check_users_list()
        for project in self.resources['projects']:
            print("Check user datas for %s" % project['name'])
            self.check_project(project['name'])
            self.check_files_in_project(project['name'],
                                        [f['name'] for f in project['files']])
            self.check_reviews_on_project(project['name'], project['issues'])
        for user in self.resources['local_users']:
            print("Check user %s can log in ..." % user['username'], end='')
            if self.simple_login(user['username'],
                                 user['password']):
                print("OK")
            else:
                print("FAIL")
                exit(1)


c = SFchecker()
c.checker()
