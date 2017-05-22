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

import config
import shutil
import time

from utils import Base
from utils import ManageSfUtils
from utils import GerritGitUtils
from utils import create_random_str
from utils import set_private_key
from utils import skipIfIssueTrackerMissing
from utils import get_issue_tracker_utils

from pysflib.sfgerrit import GerritUtils


TEST_MSGS = [
    ('bug: %s', 'Closed'),
    ('Bug: %s', 'Closed'),
    ('bug: #%s', 'Closed'),
    ('Bug: #%s', 'Closed'),
    ('issue: %s', 'Closed'),
    ('Issue: %s', 'Closed'),
    ('issue: #%s', 'Closed'),
    ('Issue: #%s', 'Closed'),
    ('related to: %s', 'In Progress'),
    ('Related-To: #%s', 'In Progress'),
]


class TestGerritHooks(Base):
    """ Functional tests that validate Gerrit hooks.
    """
    @classmethod
    def setUpClass(cls):
        cls.msu = ManageSfUtils(config.GATEWAY_URL)

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.projects = []
        self.dirs_to_delete = []
        self.issues = []
        self.u = config.ADMIN_USER
        self.u2 = config.USER_2
        self.rm = get_issue_tracker_utils(
            auth_cookie=config.USERS[config.ADMIN_USER]['auth_cookie'])
        self.gu = GerritUtils(
            config.GATEWAY_URL,
            auth_cookie=config.USERS[self.u]['auth_cookie'])
        self.gu2 = GerritUtils(
            config.GATEWAY_URL,
            auth_cookie=config.USERS[self.u2]['auth_cookie'])
        self.gu.add_pubkey(config.USERS[self.u]["pubkey"])
        priv_key_path = set_private_key(config.USERS[self.u]["privkey"])
        self.gitu = GerritGitUtils(self.u,
                                   priv_key_path,
                                   config.USERS[self.u]['email'])

    def tearDown(self):
        for issue in self.issues:
            self.rm.delete_issue(issue)
        for name in self.projects:
            self.msu.deleteProject(name, self.u)
        for dirs in self.dirs_to_delete:
            shutil.rmtree(dirs)

    def create_project(self, name, user,
                       options=None):
        self.msu.createProject(name, user,
                               options)
        self.projects.append(name)

    def _test_update_issue_hooks(self, comment_template, status,
                                 pname):
        """ A referenced issue in commit msg triggers the hook
        """
        # Be sure the project does not exist
        self.msu.deleteProject(pname, self.u)

        # Create the project
        self.create_project(pname, self.u)
        # Put USER_2 as core for the project
        self.gu.add_group_member(self.u2, "%s-core" % pname)

        # Create an issue on the project
        issue_id = self.rm.create_issue(pname, "There is a problem")

        # Clone and commit something
        url = "ssh://%s@%s:29418/%s" % (self.u, config.GATEWAY_HOST,
                                        pname)
        clone_dir = self.gitu.clone(url, pname)
        cmt_msg = comment_template % issue_id
        self.gitu.add_commit_and_publish(clone_dir, 'master', cmt_msg)

        # Check issue status (Gerrit hook updates the issue to in progress)
        attempt = 0
        while True:
            if self.rm.test_issue_status(issue_id, 'In Progress'):
                break
            if attempt > 10:
                break
            time.sleep(1)
            attempt += 1
        self.assertTrue(self.rm.test_issue_status(issue_id, 'In Progress'))
        self._test_merging(pname, issue_id, status)

    def _test_merging(self, pname, issue_id, status):
        # Get the change id and merge the patch
        change_ids = self.gu.get_my_changes_for_project(pname)
        self.assertGreater(len(change_ids), 0)
        change_id = change_ids[0]
        self.gu.submit_change_note(change_id, "current", "Code-Review", "2")
        self.gu.submit_change_note(change_id, "current", "Workflow", "1")
        self.gu.submit_change_note(change_id, "current", "Verified", "2")
        self.gu2.submit_change_note(change_id, "current", "Code-Review", "2")
        self.assertTrue(self.gu.submit_patch(change_id, "current"))

        # Check issue status (Gerrit hook updates the issue to in progress)
        attempt = 0
        while True:
            if self.rm.test_issue_status(issue_id, status):
                break
            if attempt > 10:
                break
            time.sleep(1)
            attempt += 1
        self.assertTrue(self.rm.test_issue_status(issue_id, status))

    @skipIfIssueTrackerMissing()
    def test_gerrit_hook(self):
        """test various commit messages triggering a hook"""
        for template, final_status in TEST_MSGS:
            pname = 'p_%s' % create_random_str()
            self._test_update_issue_hooks(template, final_status, pname)

    @skipIfIssueTrackerMissing()
    def test_gerrit_hook_namespace(self):
        """test various commit messages triggering a hook (with namespace)"""
        for template, final_status in TEST_MSGS:
            pname = 'my_namespace/%s' % create_random_str()
            self._test_update_issue_hooks(template, final_status, pname)
