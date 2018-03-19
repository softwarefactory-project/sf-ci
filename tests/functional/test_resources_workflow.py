# Copyright (C) 2016 Red Hat
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
import re
import config
import shutil
import requests

from subprocess import Popen

from utils import Base
from utils import set_private_key
from utils import GerritGitUtils
from utils import JobUtils
from utils import create_random_str
from utils import skipIfServiceMissing
from utils import get_gerrit_utils

from pysflib.sfstoryboard import SFStoryboard


class TestResourcesWorkflow(Base):

    def setUp(self):
        super(TestResourcesWorkflow, self).setUp()
        priv_key_path = set_private_key(
            config.USERS[config.ADMIN_USER]["privkey"])
        self.gitu_admin = GerritGitUtils(
            config.ADMIN_USER,
            priv_key_path,
            config.USERS[config.ADMIN_USER]['email'])
        self.gu = get_gerrit_utils("admin")
        self.ju = JobUtils()

        self.dirs_to_delete = []

    def tearDown(self):
        super(TestResourcesWorkflow, self).tearDown()
        for dirs in self.dirs_to_delete:
            shutil.rmtree(dirs)

    def ssh_run_cmd(self, sshkey_priv_path, user, host, subcmd):
        host = '%s@%s' % (user, host)
        sshcmd = ['ssh', '-o', 'LogLevel=ERROR',
                  '-o', 'StrictHostKeyChecking=no',
                  '-o', 'UserKnownHostsFile=/dev/null', '-i',
                  sshkey_priv_path, host]
        cmd = sshcmd + subcmd

        devnull = open(os.devnull, 'wb')
        p = Popen(cmd, stdout=devnull, stderr=devnull)
        return p.communicate(), p.returncode

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

    def set_resources_then_direct_push(self, fpath,
                                       resources=None, mode='add'):
        config_clone_dir = self.clone_as_admin("config")
        path = os.path.join(config_clone_dir, fpath)
        if mode == 'add':
            file(path, 'w').write(resources)
        elif mode == 'del':
            os.unlink(path)
        change_sha = self.commit_direct_push_as_admin(
            config_clone_dir,
            "Add new resources for functional tests")
        config_update_result = self.ju.wait_for_config_update(
            change_sha, return_result=True)
        self.assertTrue('SUCCESS' in config_update_result,
                        config_update_result)

    def propose_resources_change_check_ci(
            self, fpath, resources=None,
            mode='add', expected_note=1, msg=None):

        config_clone_dir = self.clone_as_admin("config")
        path = os.path.join(config_clone_dir, fpath)
        if mode == 'add':
            file(path, 'w').write(resources)
        elif mode == 'del':
            os.unlink(path)

        if not msg:
            msg = "Validate resources"
        if mode == 'add':
            change_sha = self.gitu_admin.add_commit_and_publish(
                config_clone_dir, "master", msg, fnames=[path])
        if mode == 'del':
            change_sha = self.gitu_admin.add_commit_for_all_new_additions(
                config_clone_dir, msg, publish=True)

        change_nr = self.gu.get_change_number(change_sha)
        note = self.gu.wait_for_verify(
            change_nr, ['jenkins', 'zuul'], timeout=180)
        self.assertEqual(note, expected_note)

    def get_resources(self):
        gateau = config.USERS[config.ADMIN_USER]['auth_cookie']
        resp = requests.get("%s/manage/v2/resources/" % config.GATEWAY_URL,
                            cookies={'auth_pubtkt': gateau})
        return resp.json()

    def test_validate_wrong_resource_workflow(self):
        """ Check resources - wrong model is detected by config-check """
        # This resource is not correct
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  groups:
    %s:
      unknown-key: value
      description: test for functional test
"""
        # Add the resource file with review then check CI
        resources = resources % name
        self.propose_resources_change_check_ci(fpath,
                                               resources=resources,
                                               mode='add',
                                               expected_note=-1)

    def test_validate_correct_resource_workflow(self):
        """ Check resources - good model is detected by config-check """
        # This resource is correct
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  groups:
    %s:
      description: test for functional test
      members:
        - user2@sftests.com
"""
        # Add the resource file with review then check CI
        resources = resources % name
        self.propose_resources_change_check_ci(fpath,
                                               resources=resources,
                                               mode='add')

    def test_validate_resources_deletion(self):
        """ Check resources - deletions detected and authorized via flag """
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  groups:
    %s:
      description: test for functional test
      members: []
"""
        # Add the resources file w/o review
        resources = resources % name
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')

        # Remove the resource file via the review
        self.propose_resources_change_check_ci(fpath,
                                               mode='del',
                                               expected_note=-1)

        # Remove the resource file with "allow-delete" flag via the review
        shutil.rmtree(os.path.join(self.gitu_admin.tempdir, 'config'))
        msg = "Remove resource with flag\nsf-resources: allow-delete"
        self.propose_resources_change_check_ci(fpath,
                                               mode='del',
                                               msg=msg)

    @skipIfServiceMissing('storyboard')
    def test_CUD_project(self):
        """ Check resources - ops on project work as expected """
        sclient = SFStoryboard(config.GATEWAY_URL + "/storyboard_api",
                               config.USERS[config.USER_4]['auth_cookie'])
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  projects:
    %(pname)s:
      description: An awesome project
      issue-tracker: SFStoryboard
      source-repositories:
        - %(pname)s/%(r1name)s
  repos:
    %(pname)s/%(r1name)s:
      description: The server part
      acl: %(pname)s
  acls:
    %(pname)s:
      file: |
        [access "refs/*"]
          read = group Anonymous Users
"""
        tmpl_keys = {'pname': create_random_str(),
                     'r1name': create_random_str()}

        resources = resources % tmpl_keys
        # Add the resources file w/o review
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')

        # Some checks to validate stuff have been created
        projects = [p.name for p in sclient.projects.get_all()]
        self.assertIn(
            "%s/%s" % (tmpl_keys['pname'], tmpl_keys['r1name']),
            projects)
        project_groups = [p.name for p in
                          sclient.project_groups.get_all()]
        self.assertIn(tmpl_keys['pname'], project_groups)

        # Modify the project resource
        resources = """resources:
  projects:
    %(pname)s:
      description: An awesome project
      issue-tracker: SFStoryboard
      source-repositories:
        - %(pname)s/%(r1name)s
        - %(pname)s/%(r2name)s
  repos:
    %(pname)s/%(r1name)s:
      description: The server part
      acl: %(pname)s
    %(pname)s/%(r2name)s:
      description: The server part
      acl: %(pname)s
  acls:
    %(pname)s:
      file: |
        [access "refs/*"]
          read = group Anonymous Users
"""
        tmpl_keys.update({'r2name': create_random_str()})
        resources = resources % tmpl_keys
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Some checks to validate stuff have been updated
        projects = [p.name for p in sclient.projects.get_all()]
        for name in (tmpl_keys['r1name'], tmpl_keys['r2name']):
            self.assertIn(
                "%s/%s" % (tmpl_keys['pname'], name), projects)
        project_groups = [p.name for p in
                          sclient.project_groups.get_all()]
        self.assertIn(tmpl_keys['pname'], project_groups)

        # Del the resources file w/o review
        self.set_resources_then_direct_push(fpath,
                                            mode='del')

        # Check the project group has been deleted
        # Note the project (in storyboard) is not deleted
        # this is a current limitation of the API (01/13/2017)
        project_groups = [p.name for p in
                          sclient.project_groups.get_all()]
        self.assertFalse(tmpl_keys['pname'] in project_groups)

    def test_CUD_group(self):
        """ Check resources - ops on group work as expected """
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  groups:
    %s:
      description: test for functional test
      members:
        - user2@sftests.com
        - user3@sftests.com
"""
        # Add the resources file w/o review
        resources = resources % name
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Check members on Gerrit
        gid = self.gu.get_group_id(name)
        members = [m['email'] for m in self.gu.get_group_members(gid)]
        self.assertIn("user2@sftests.com", members)
        self.assertIn("user3@sftests.com", members)
        # Modify resources Add/Remove members w/o review
        resources = """resources:
  groups:
    %s:
      description: test for functional test
      members:
        - user4@sftests.com
        - user2@sftests.com
"""
        resources = resources % name
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Check members on Gerrit
        gid = self.gu.get_group_id(name)
        members = [m['email'] for m in self.gu.get_group_members(gid)]
        self.assertIn("user4@sftests.com", members)
        self.assertIn("user2@sftests.com", members)
        self.assertNotIn("user3@sftests.com", members)
        # Del the resources file w/o review
        self.set_resources_then_direct_push(fpath,
                                            mode='del')
        # Check the group has been deleted
        self.assertFalse(
            self.gu.get_group_id(name))

    def test_CD_repo(self):
        """ Check resources - ops on git repositories work as expected """
        fpath = "resources/%s.yaml" % create_random_str()
        name = create_random_str()
        resources = """resources:
  repos:
    %s:
      description: test for functional test
      default-branch: br1
      branches:
        br1: HEAD
        br2: HEAD
        master: '0'
"""
        # Add the resources file w/o review
        resources = resources % name
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Check the project has been created
        self.assertTrue(self.gu.project_exists(name))
        # Check branches
        branches = self.gu.g.get('/projects/%s/branches/' % name)
        for wref in ("HEAD", "br1", "br2"):
            found = False
            for ref in branches:
                if found:
                    continue
                if ref['ref'].endswith(wref):
                    found = True
                    if ref['ref'] == 'HEAD' and ref['revision'] != "br1":
                        raise Exception("Wrong default branch")
            if not found:
                raise Exception("Requested branch %s not found" % wref)
        # Del the resources file w/o review
        self.set_resources_then_direct_push(fpath,
                                            mode='del')
        # Check the project has been deleted
        self.assertFalse(self.gu.project_exists(name))

    def test_CRUD_resources(self):
        """ Check resources - bulk ops on resources work as expected """
        fpath = "resources/%s.yaml" % create_random_str()
        tmpl_keys = {'pname': create_random_str(),
                     'r1name': create_random_str(),
                     'r2name': create_random_str(),
                     'aname': create_random_str(),
                     'g1name': create_random_str(),
                     'g2name': create_random_str()}
        resources = """resources:
  projects:
    %(pname)s:
      description: An awesome project
      contacts:
        - contact@grostest.com
      source-repositories:
        - %(pname)s/%(r1name)s
        - %(pname)s/%(r2name)s
      website: http://ichiban-cloud.io
      documentation: http://ichiban-cloud.io/docs
      issue-tracker-url: http://ichiban-cloud.bugtrackers.io
  repos:
    %(pname)s/%(r1name)s:
      description: The server part
      acl: %(aname)s
    %(pname)s/%(r2name)s:
      description: The client part
      acl: %(aname)s
  acls:
    %(aname)s:
      file: |
        [access "refs/*"]
          read = group Anonymous Users
          read = group %(pname)s/%(g2name)s
          owner = group %(pname)s/%(g1name)s
        [access "refs/heads/*"]
          label-Code-Review = -2..+2 group %(pname)s/%(g2name)s
          label-Verified = -2..+2 group %(pname)s/%(g1name)s
          label-Workflow = -1..+1 group %(pname)s/%(g2name)s
          submit = group %(pname)s/%(g2name)s
          read = group Anonymous Users
          read = group %(pname)s/%(g2name)s
        [access "refs/meta/config"]
          read = group %(pname)s/%(g2name)s
        [receive]
          requireChangeId = true
        [submit]
          mergeContent = false
          action = fast forward only
      groups:
        - %(pname)s/%(g1name)s
        - %(pname)s/%(g2name)s
  groups:
    %(pname)s/%(g1name)s:
      members:
        - user2@sftests.com
    %(pname)s/%(g2name)s:
      members:
        - user3@sftests.com
        - user4@sftests.com
"""
        # Add the resources file w/o review
        resources = resources % tmpl_keys
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Check resources have been created
        self.assertTrue(self.gu.project_exists(
                        os.path.join(tmpl_keys['pname'],
                                     tmpl_keys['r1name'])))
        self.assertTrue(self.gu.project_exists(
                        os.path.join(tmpl_keys['pname'],
                                     tmpl_keys['r2name'])))
        gid = self.gu.get_group_id(os.path.join(tmpl_keys['pname'],
                                                tmpl_keys['g1name']))
        members = [m['email'] for m in self.gu.get_group_members(gid)]
        self.assertEqual(len(members), 1)
        self.assertIn("user2@sftests.com", members)
        gid2 = self.gu.get_group_id(os.path.join(tmpl_keys['pname'],
                                                 tmpl_keys['g2name']))
        members = [m['email'] for m in self.gu.get_group_members(gid2)]
        self.assertEqual(len(members), 2)
        self.assertIn("user3@sftests.com", members)
        self.assertIn("user4@sftests.com", members)
        # Verify ACLs have been written for both repo
        for r in ('r1name', 'r2name'):
            rname = os.path.join(tmpl_keys['pname'], tmpl_keys[r])
            acl = self.gu.g.get('access/?project=%s' % rname)
            self.assertIn(
                gid2,
                acl[rname]['local']['refs/heads/*']
                   ['permissions']['submit']['rules'].keys())
        # Verify the resources endpoint know about what we pushed
        res = self.get_resources()
        self.assertIn(tmpl_keys['pname'],
                      res['resources']['projects'].keys())
        self.assertIn(tmpl_keys['aname'],
                      res['resources']['acls'].keys())
        self.assertIn(os.path.join(tmpl_keys['pname'], tmpl_keys['g1name']),
                      res['resources']['groups'].keys())
        self.assertIn(os.path.join(tmpl_keys['pname'], tmpl_keys['g2name']),
                      res['resources']['groups'].keys())
        self.assertIn(os.path.join(tmpl_keys['pname'], tmpl_keys['r1name']),
                      res['resources']['repos'].keys())
        self.assertIn(os.path.join(tmpl_keys['pname'], tmpl_keys['r2name']),
                      res['resources']['repos'].keys())
        # Modify the ACL to verify repos ACL are updated
        resources = re.sub('submit = group .*',
                           'submit = group %s' % os.path.join(
                               tmpl_keys['pname'], tmpl_keys['g1name']),
                           resources)
        self.set_resources_then_direct_push(fpath,
                                            resources=resources,
                                            mode='add')
        # Verify ACLs have been updated for both repo
        for r in ('r1name', 'r2name'):
            rname = os.path.join(tmpl_keys['pname'], tmpl_keys[r])
            acl = self.gu.g.get('access/?project=%s' % rname)
            self.assertIn(
                gid,
                acl[rname]['local']['refs/heads/*']
                          ['permissions']['submit']['rules'].keys())
        # Now let's remove all that awesome resources
        self.set_resources_then_direct_push(fpath,
                                            mode='del')
        # Check resources have been deleted
        self.assertFalse(self.gu.project_exists(
                         os.path.join(tmpl_keys['pname'],
                                      tmpl_keys['r1name'])))
        self.assertFalse(self.gu.project_exists(
                         os.path.join(tmpl_keys['pname'],
                                      tmpl_keys['r2name'])))
        self.assertFalse(self.gu.get_group_id(
            os.path.join(tmpl_keys['pname'],
                         tmpl_keys['g1name'])))
        self.assertFalse(self.gu.get_group_id(
            os.path.join(tmpl_keys['pname'],
                         tmpl_keys['g2name'])))
        res = self.get_resources()
        projects = res['resources'].get('projects', {})
        acls = res['resources'].get('acls', {})
        groups = res['resources'].get('groups', {})
        repos = res['resources'].get('repos', {})
        self.assertNotIn(tmpl_keys['pname'], projects.keys())
        self.assertNotIn(tmpl_keys['aname'], acls.keys())
        self.assertNotIn(os.path.join(tmpl_keys['pname'], tmpl_keys['g1name']),
                         groups.keys())
        self.assertNotIn(os.path.join(tmpl_keys['pname'], tmpl_keys['g2name']),
                         groups.keys())
        self.assertNotIn(os.path.join(tmpl_keys['pname'], tmpl_keys['r1name']),
                         repos.keys())
        self.assertNotIn(os.path.join(tmpl_keys['pname'], tmpl_keys['r2name']),
                         repos.keys())

    def test_GET_resources(self):
        """ Check resources - GET resources works as expected"""
        cookies = dict(auth_pubtkt=config.USERS[config.USER_1]['auth_cookie'])
        ret = requests.get("%s/manage/v2/resources/" % config.GATEWAY_URL,
                           cookies=cookies)
        self.assertIn('resources', ret.json())
