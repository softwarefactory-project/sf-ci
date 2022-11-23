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
import yaml

import config

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

    def checker(self):
        for project in self.resources['projects']:
            print("Check project %s" % project['name'])
            self.check_project(project['name'])
            self.check_files_in_project(project['name'],
                                        [f['name'] for f in project['files']])


c = SFchecker()
c.checker()
