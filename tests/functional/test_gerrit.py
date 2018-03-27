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
import shutil
import time
import requests
import config
import logging

from utils import Base
from utils import set_private_key
from utils import ResourcesUtils
from utils import GerritGitUtils
from utils import create_random_str
from utils import get_gerrit_utils
from utils import gerrit_version
from utils import skipIf


logger = logging.getLogger(__name__)


class TestGerrit(Base):
    """ Functional tests that validate some gerrit behaviors.
    """
    def setUp(self):
        super(TestGerrit, self).setUp()
        self.projects = []
        self.clone_dirs = []
        self.dirs_to_delete = []
        self.ru = ResourcesUtils()

    def tearDown(self):
        super(TestGerrit, self).tearDown()
        for name in self.projects:
            self.ru.direct_delete_repo(name)
        for dirs in self.dirs_to_delete:
            shutil.rmtree(dirs)

    def create_project(self, name):
        self.ru.direct_create_repo(name)
        self.projects.append(name)

    def _prepare_review_submit_testing(self, data=None):
        pname = 'p_%s' % create_random_str()
        self.create_project(pname)
        gu = get_gerrit_utils("admin")
        self.assertTrue(gu.project_exists(pname))
        priv_key_path = set_private_key(
            config.USERS[config.ADMIN_USER]["privkey"])
        gitu = GerritGitUtils(config.ADMIN_USER,
                              priv_key_path,
                              config.USERS[config.ADMIN_USER]['email'])
        url = "ssh://%s@%s:29418/%s" % (config.ADMIN_USER, config.GATEWAY_HOST,
                                        pname)
        clone_dir = gitu.clone(url, pname)
        self.dirs_to_delete.append(os.path.dirname(clone_dir))

        if not data:
            gitu.add_commit_and_publish(clone_dir, "master", "Test commit")
        else:
            file(os.path.join(clone_dir, "file"), 'w').write(data[1])
            gitu.add_commit_and_publish(clone_dir, "master", "Test commit",
                                        fnames=[data[0]])

        change_ids = gu.get_my_changes_for_project(pname)
        self.assertEqual(len(change_ids), 1)
        change_id = change_ids[0]

        return change_id, gu, pname

    def test_review_labels(self):
        """ Test if list of review labels are as expected
        """
        change_id, gu, _ = self._prepare_review_submit_testing()

        logger.info("Looking for labels for change %s" % change_id)
        labels = gu.get_labels_list_for_change(change_id)

        self.assertIn('Workflow', labels)
        self.assertIn('Code-Review', labels)
        self.assertIn('Verified', labels)
        self.assertEqual(len(labels.keys()), 3)

    def test_review_submit_approval(self):
        """ Test submit criteria - CR(+2s), V(+1), W(+1)
        """
        change_id, gu, _ = self._prepare_review_submit_testing()

        gu.submit_change_note(change_id, "current", "Code-Review", "1")
        self.assertFalse(gu.submit_patch(change_id, "current"))

        gu.submit_change_note(change_id, "current", "Verified", "2")
        self.assertFalse(gu.submit_patch(change_id, "current"))

        gu.submit_change_note(change_id, "current", "Workflow", "1")
        self.assertFalse(gu.submit_patch(change_id, "current"))

        gu.submit_change_note(change_id, "current", "Code-Review", "2")
        self.assertTrue(gu.submit_patch(change_id, "current"))

    def test_plugins_installed(self):
        """ Test if plugins are present
        """
        gu = get_gerrit_utils("admin")
        plugins = gu.list_plugins()
        self.assertIn('download-commands', plugins)
        self.assertIn('avatars-gravatar', plugins)
        self.assertIn('reviewers-by-blame', plugins)

    def test_check_download_commands(self):
        """ Test if download commands plugin works
        """
        change_id, gu, _ = self._prepare_review_submit_testing()
        if "2.11" in gerrit_version:
            # pysflib/sfgerrit get_change does not have the same interface
            resp = gu.get_change_last_patchset(change_id)
        else:
            resp = gu.get_change(change_id)

        self.assertIn("current_revision", resp)
        self.assertIn("revisions", resp)
        current_rev = resp["current_revision"]
        fetch = resp["revisions"][current_rev]["fetch"]
        self.assertGreater(fetch.keys(), 0)

    def test_check_add_automatic_reviewers(self):
        """ Test if reviewers-by-blame plugin works
        """
        data = "this\nis\na\ncouple\nof\nlines"
        change_id, gu, pname = self._prepare_review_submit_testing(
            ('file', data))

        # Merge the change
        gu.submit_change_note(change_id, "current", "Code-Review", "2")
        gu.submit_change_note(change_id, "current", "Verified", "2")
        gu.submit_change_note(change_id, "current", "Workflow", "1")
        self.assertTrue(gu.submit_patch(change_id, "current"))

        gu2 = get_gerrit_utils(config.USER_2)
        # Change the file we have commited with Admin user
        gu2.add_pubkey(config.USERS[config.USER_2]["pubkey"])
        priv_key_path = set_private_key(config.USERS[config.USER_2]["privkey"])
        gitu2 = GerritGitUtils(
            config.USER_2, priv_key_path,
            config.USERS[config.USER_2]['email'])
        url = "ssh://%s@%s:29418/%s" % (
            config.USER_2, config.GATEWAY_HOST, pname)
        clone_dir = gitu2.clone(url, pname)
        self.dirs_to_delete.append(os.path.dirname(clone_dir))
        data = ['this', 'is', 'some', 'lines']
        file(os.path.join(clone_dir, "file"), 'w').write("\n".join(data))
        gitu2.add_commit_and_publish(
            clone_dir, "master", "Test commit", fnames=["file"])
        # Get the change id
        change_ids = gu2.get_my_changes_for_project(pname)
        self.assertEqual(len(change_ids), 1)
        change_id = change_ids[0]
        # Verify first_u has been automatically added to reviewers
        for retry in range(3):
            if len(gu2.get_reviewers(change_id)) > 0:
                break
            time.sleep(1)
        reviewers = gu2.get_reviewers(change_id)
        self.assertEqual(len(reviewers), 1)
        self.assertEqual(reviewers[0], config.ADMIN_USER)

    @skipIf("2.11" in gerrit_version, "Gerrit-2.14 is needed for this test")
    def test_gerrit_version(self):
        """ Test if correct Gerrit version is running
        """
        gu = get_gerrit_utils("admin")
        self.assertIn("2.14", gu.get("config/server/version"))

    def test_gitweb_access(self):
        """ Test if gitweb access works correctly
        """
        pname = 'p_%s' % create_random_str()
        self.create_project(pname)

        # Test anonymous access to a repo
        url = "%s/r/gitweb?p=%s.git" % (config.GATEWAY_URL, pname)
        expected_title = "%s.git/summary" % pname

        resp = requests.get(url)
        self.assertTrue(resp.url.endswith('/r/gitweb?p=%s.git' % pname))
        self.assertTrue(expected_title in resp.text)
