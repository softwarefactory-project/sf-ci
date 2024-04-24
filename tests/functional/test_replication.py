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
import config
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

    def get_config_sha(self):
        sha = run(
            "sudo cat /root/config/.git/refs/heads/master",
            shell=True, stdout=PIPE).stdout.strip().decode()
        return sha

    def config_push(self, prev_sha, commit):
        run("sudo sh -c 'cd /root/config; /usr/local/bin/git-review -s'",
            shell=True)
        run("sudo sh -c 'cd /root/config; git add -A'",
            shell=True)
        run("sudo sh -c 'cd /root/config; git commit -m %s'" % commit,
            shell=True)
        sha = self.get_config_sha()
        if prev_sha != sha:
            logger.info('Pushing commit %s' % sha)
            run("sudo sh -c 'cd /root/config; git push gerrit master'",
                shell=True)
            return sha

    def create_config_section(self):
        logger.info("Add the replication config section")
        host = 'root@%s' % config.GATEWAY_HOST
        mirror_repo_path = r'%s/\${name}.git' % self.rep_dir
        url = '%s:%s' % (host, mirror_repo_path)
        path = '/root/config/gerrit/replication.config'
        run("sudo git config -f %s --remove-section remote.test_project" %
            path, shell=True)
        run("sudo git config -f %s --add remote.test_project.projects config" %
            path, shell=True)
        run("sudo git config -f %s --add remote.test_project.url %s" %
            (path, url), shell=True)

        prev_sha = self.get_config_sha()
        change_sha = self.config_push(
            prev_sha, "Add-replication-test-section")
        if change_sha:
            logger.info("Waiting for config-update on %s" % change_sha)
            self.ju.wait_for_config_update(change_sha)
            ret = run(['sudo', 'grep', 'test_project',
                       '/etc/gerrit/replication.config'])
            if ret.returncode == 0:
                return
            raise Exception('replication.config has not been updated (add)')

    def check_replicated(self):
        for retry in range(50):
            if run("sudo ls " + os.path.join(
                    self.rep_dir, 'config.git'),
                   shell=True).returncode == 0:
                return True
            else:
                time.sleep(3)

    def test_replication(self):
        """ Test gerrit replication for review process
        """
        # Be sure instance host key is inside the known_hosts
        run('ssh-keyscan %s | sudo tee -a ' % config.GATEWAY_HOST +
            '/var/lib/gerrit/.ssh/known_hosts',
            shell=True)
        # Add gerrit_service_rsa ass authorized key for root
        run('cat /var/lib/software-factory/bootstrap-data/' +
            'ssh_keys/gerrit_service_rsa.pub | sudo tee -a ' +
            '/root/.ssh/authorized_keys',
            shell=True)

        # Create new section for this project in replication.config
        self.create_config_section()

        # Verify if gerrit replicated the repo
        if not self.check_replicated():
            raise
