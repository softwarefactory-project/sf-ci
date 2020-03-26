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
import time
import uuid
import logging

from utils import Base
from utils import JobUtils

from subprocess import PIPE, run

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestProjectReplication(Base):
    """ Functional tests to verify the gerrit replication feature
    """
    def setUp(self):
        super(TestProjectReplication, self).setUp()
        self.ju = JobUtils()
        self.rep_dir = os.path.join('/root', str(uuid.uuid4()))
        # Ensure clean state
        self.delete_config_section()

    def config_push(self, prev_sha, commit=None):
        if not commit:
            commit = "Add all the additions"
        run('git review -s',
            shell=True, cwd='/root/config')
        run('git add -A',
            shell=True, cwd='/root/config')
        run("git commit -m '%s'" % commit,
            shell=True, cwd='/root/config')
        sha = open("/root/config/.git/refs/heads/master").read().strip()
        if prev_sha != sha:
            logger.info('Pushing commit %s' % sha)
            run('git push gerrit master', shell=True,
                cwd='/root/config')
            return sha.strip()

    def create_config_section(self):
        logger.info("Add the replication config section")
        host = 'root@localhost'
        mirror_repo_path = r'%s/\${name}.git' % self.rep_dir
        url = '%s:%s' % (host, mirror_repo_path)
        path = '/root/config/gerrit/replication.config'
        run("git config -f %s --remove-section remote.test_project" %
            path, shell=True)
        run("git config -f %s --add remote.test_project.projects config" %
            path, shell=True)
        run("git config -f %s --add remote.test_project.url %s" %
            (path, url), shell=True)

        prev_sha = open(
            "/root/config/.git/refs/heads/master").read().strip()
        change_sha = self.config_push(
            prev_sha, "Add replication test section")
        if change_sha:
            logger.info("Waiting for config-update on %s" % change_sha)
            self.ju.wait_for_config_update(change_sha)
            ret = run(['grep', 'test_project',
                       '/etc/gerrit/replication.config'])
            if ret.returncode == 0:
                return
            raise Exception('replication.config has not been updated (add)')

    def delete_config_section(self):
        logger.info("Remove the replication config section")
        path = '/root/config/gerrit/replication.config'
        run(["git", "config", "-f", path,
             "--remove-section", "remote.test_project"])
        prev_sha = open(
            "/root/config/.git/refs/heads/master").read().strip()
        change_sha = self.config_push(
            prev_sha, "Remove replication test section")
        if change_sha:
            logger.info("Waiting for config-update on %s" % change_sha)
            self.ju.wait_for_config_update(change_sha)
            ret = run(['grep', 'test_project',
                       '/etc/gerrit/replication.config'])
            if ret.returncode != 0:
                return
            raise Exception('replication.config has not been updated (rm)')

    def check_replicated(self):
        for retry in range(50):
            if os.path.isdir(
                    os.path.join(self.rep_dir, 'config.git')):
                return True
            else:
                time.sleep(3)

    def test_replication(self):
        """ Test gerrit replication for review process
        """
        # Be sure instance host key is inside the known_hosts
        ret = run('ssh-keyscan localhost', shell=True,
                  stdout=PIPE, stderr=PIPE)
        host_fingerprint = ret.stdout.decode()
        with open('/var/lib/gerrit/.ssh/known_hosts', 'w') as fd:
            fd.write(host_fingerprint)
        # Add gerrit_service_rsa ass authorized key for root
        gerrit_service_rsa_pub = open(
            '/var/lib/software-factory/bootstrap-data/' +
            'ssh_keys/gerrit_service_rsa.pub').read()
        with open('/root/.ssh/authorized_keys', 'a') as fd:
            fd.write(gerrit_service_rsa_pub)

        # Create new section for this project in replication.config
        self.create_config_section()

        # Verify if gerrit replicated the repo
        if not self.check_replicated():
            raise
