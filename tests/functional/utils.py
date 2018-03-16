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

from copy import deepcopy
import json
import os
import re
import unittest
import subprocess
import shlex
import shutil
import stat
import tempfile
import requests
import time
import uuid
import yaml

import logging
import pkg_resources

from distutils.version import StrictVersion
from subprocess import Popen, PIPE

import config


logging.getLogger("requests").setLevel(logging.WARNING)
logging.captureWarnings(True)
logging.basicConfig(format="%(asctime)s: %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# for easier imports
skipIf = unittest.skipIf
skip = unittest.skip

services = config.groupvars['roles'].keys()


def cmp_version(v1, v2):
    return StrictVersion(v1) < StrictVersion(v2)


def is_present(service):
    return service in services


def has_issue_tracker():
    return set(config.ISSUE_TRACKERS) & set(services)


def skipIfStrInFile(check_str, path):
    return skipIf(check_str in file(path).read(),
                  'File %s contains %s' % (path, check_str))


def skipIfProvisionVersionLesserThan(wanted_version):
    return skipIf(cmp_version(os.environ.get("PROVISIONED_VERSION", "0.0"),
                              wanted_version),
                  'This instance provisionned data is not supported (%s)' %
                  wanted_version)


def skipIfServiceMissing(service):
    return skipIf(service not in services,
                  'This instance of SF is not running %s' % service)


def skipIfServicePresent(service):
    return skipIf(service in services,
                  'This instance of SF is running %s' % service)


def get_module_version(module):
    m = module
    if not isinstance(m, basestring):
        m = module.__name__
    try:
        return pkg_resources.get_distribution(m).version
    except pkg_resources.DistributionNotFound:
        # module not available, return dummy version
        return "0"


def create_random_str():
    return str(uuid.uuid4())


def set_private_key(priv_key):
    tempdir = tempfile.mkdtemp()
    priv_key_path = os.path.join(tempdir, 'user.priv')
    file(priv_key_path, 'w').write(priv_key)
    os.chmod(priv_key_path, stat.S_IREAD | stat.S_IWRITE)
    return priv_key_path


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)


def get_cookie(username, password):
    url = "%(auth_url)s/auth/login" % {'auth_url': config.GATEWAY_URL}
    resp = requests.post(url, params={'username': username,
                                      'password': password,
                                      'back': '/'},
                         allow_redirects=False)
    return resp.cookies.get('auth_pubtkt', '')


def ssh_run_cmd(sshkey_priv_path, user, host, subcmd, verbose=False):
    host = '%s@%s' % (user, host)
    sshcmd = ['ssh', '-o', 'LogLevel=ERROR',
              '-o', 'StrictHostKeyChecking=no',
              '-o', 'UserKnownHostsFile=/dev/null', '-i',
              sshkey_priv_path, host]
    if verbose:
        sshcmd += ['-v', ]
    cmd = sshcmd + subcmd
    logger.info('Running remote command: %s' % ' '.join(cmd))
    p = Popen(cmd, stdout=PIPE)
    return p.communicate()


class Base(unittest.TestCase):
    def setUp(self):
        logger.debug("Test case setUp")

    def tearDown(self):
        logger.debug("Test case tearDown")


class Tool:
    def __init__(self):
        self.env = os.environ.copy()

    def exe(self, cmd, cwd=None):
        logger.debug('Starting Process "%s"' % cmd)
        cmd = map(lambda s: s.decode('utf8'), shlex.split(cmd.encode('utf8')))
        ocwd = os.getcwd()
        output = ''
        if cwd:
            os.chdir(cwd)
        try:
            self.env['LC_ALL'] = 'en_US.UTF-8'
            output = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT,
                env=self.env)
            if output:
                output = unicode(output, encoding='utf8')
                logger.debug(u'Process Output [%s]' % output.strip())
        except subprocess.CalledProcessError as err:
            if err.output:
                logger.exception(u"Process Exception: %s: [%s]" %
                                 (err, err.output))
            else:
                logger.exception(err)
        finally:
            os.chdir(ocwd)
        return output


class ManageSfUtils(Tool):
    def __init__(self, url):
        Tool.__init__(self)
        self.base_cmd = "sfmanager --url %s --auth-server-url " \
            "%s --auth %%s:%%s " % (url, config.GATEWAY_URL)

    def register_user(self, auth_user, username, email):
        passwd = config.USERS[auth_user]['password']
        cmd = self.base_cmd % (auth_user, passwd) + " sf_user create "
        cmd += "--username %s --email %s --fullname %s" % (username, email,
                                                           username)
        output = self.exe(cmd)
        return output

    def deregister_user(self, auth_user, username=None, email=None):
        passwd = config.USERS[auth_user]['password']
        cmd = self.base_cmd % (auth_user, passwd) + "sf_user delete"
        if username:
            cmd += " --username %s" % username
        else:
            cmd += " --email %s" % email
        output = self.exe(cmd)
        return output

    def create_gerrit_api_password(self, user):
        passwd = config.USERS[user]['password']
        cmd = self.base_cmd % (user, passwd) + \
            "--json gerrit_api_htpasswd generate_password"
        output = json.loads(self.exe(cmd))
        try:
            output = output["password"]
        except TypeError:
            # Legacy output
            pass
        return output

    def delete_gerrit_api_password(self, user):
        passwd = config.USERS[user]['password']
        cmd = self.base_cmd % (user, passwd) + \
            "gerrit_api_htpasswd delete_password"
        output = self.exe(cmd)
        return output

    def create_user(self, user, password, email, fullname=None):
        subcmd = (" user create --username=%s "
                  "--password=%s --email=%s "
                  "--fullname=%s" % (user, password, email, fullname or user))
        auth_user = config.ADMIN_USER
        auth_password = config.USERS[config.ADMIN_USER]['password']
        cmd = self.base_cmd % (auth_user, auth_password) + subcmd
        output = self.exe(cmd)
        return output


class GerritGitUtils(Tool):
    def __init__(self, user, priv_key_path, email):
        Tool.__init__(self)
        self.user = user
        self.email = email
        self.author = "%s <%s>" % (self.user, email)
        self.priv_key_path = priv_key_path
        self.tempdir = tempfile.mkdtemp()
        ssh_wrapper = "ssh -o StrictHostKeyChecking=no -i " \
                      "%s \"$@\"" % os.path.abspath(self.priv_key_path)
        wrapper_path = os.path.join(self.tempdir, 'ssh_wrapper.sh')
        file(wrapper_path, 'w').write(ssh_wrapper)
        os.chmod(wrapper_path, stat.S_IRWXU)
        self.env['GIT_SSH'] = wrapper_path
        self.env['GIT_COMMITTER_NAME'] = self.user
        self.env['GIT_COMMITTER_EMAIL'] = self.email

    def config_review(self, clone_dir):
        # We also ensure the domain configured in the .gitreview is
        # according the one from sfconfig.yaml. It is usefull in
        # the case we try a domain reconfigure as the .git review of the
        # config repo has been initialized with another domain.
        self.exe("sed -i 's/^host=.*/host=%s/' .gitreview" %
                 config.GATEWAY_HOST, clone_dir)
        self.exe("ssh-agent bash -c 'ssh-add %s; git review -s'" %
                 self.priv_key_path, clone_dir)
        self.exe("git reset --hard", clone_dir)

    def list_open_reviews(self, project, uri, port=29418):
        cmd = "ssh -o StrictHostKeyChecking=no -i %s"
        cmd += " -p %s %s@%s gerrit "
        cmd += "query project:%s status:open --format=JSON"
        reviews = self.exe(cmd % (os.path.abspath(self.priv_key_path),
                                  str(port),
                                  self.user,
                                  uri,
                                  project))

        # encapsulate the JSON answers so that it appears as an array
        array_json = "[" + ',\n'.join(reviews.split('\n')[:-1]) + "]"
        j = json.loads(array_json)
        # last response element is only statistics, discard it
        return j[:-1]

    def clone(self, uri, target, config_review=True):
        if not uri.startswith('ssh://'):
            raise Exception("%s doesn't start with ssh://" % uri)
        cmd = "git clone %s %s" % (uri, target)
        self.exe(cmd, self.tempdir)
        clone = os.path.join(self.tempdir, target)
        if not os.path.isdir(clone):
            raise Exception("%s is not a directory" % clone)
        self.exe('git config --add gitreview.username %s' %
                 self.user, clone)
        if config_review:
            self.config_review(clone)
        return clone

    def fetch_meta_config(self, clone_dir):
        cmd = 'git fetch origin' \
            ' refs/meta/config:refs/remotes/origin/meta/config'
        self.exe(cmd, clone_dir)
        self.exe('git checkout meta/config', clone_dir)

    def add_commit_in_branch(self, clone_dir, branch, files=None, commit=None):
        self.exe('git checkout master', clone_dir)
        if branch != 'master':
            self.exe('git checkout -b %s' % branch, clone_dir)
        if not files:
            file(os.path.join(clone_dir, 'testfile'), 'w').write('data')
            files = ['testfile']
        self.git_add(clone_dir, files)
        if not commit:
            commit = "Adding some files"
        self.exe("git commit --author '%s' -m '%s'" % (self.author, commit),
                 clone_dir)

    def add_commit_for_all_new_additions(self, clone_dir, commit=None,
                                         publish=False):
        self.exe('git checkout master', clone_dir)
        if not commit:
            commit = "Add all the additions"
        self.exe('git add -A', clone_dir)
        self.exe("git commit --author '%s' -m '%s'" % (self.author, commit),
                 clone_dir)
        if publish:
            self.exe('git review -v', clone_dir)
        sha = open("%s/.git/refs/heads/master" % clone_dir).read()
        return sha.strip()

    def direct_push_branch(self, clone_dir, branch):
        self.exe('git checkout %s' % branch, clone_dir)
        self.exe('git push origin %s' % branch, clone_dir)
        self.exe('git checkout master', clone_dir)
        sha = open("%s/.git/refs/heads/%s" % (clone_dir, branch)).read()
        return sha.strip()

    def review_push_branch(self, clone_dir, branch):
        self.exe('git checkout %s' % branch, clone_dir)
        self.exe('git review', clone_dir)
        sha = open("%s/.git/refs/heads/%s" % (clone_dir, branch)).read()
        self.exe('git checkout master', clone_dir)
        return sha.strip()

    def git_add(self, clone_dir, files=[]):
        to_add = " ".join(files)
        self.exe('git add %s' % to_add, clone_dir)

    def add_commit_and_publish(self, clone_dir, branch,
                               commit_msg, commit_author=None,
                               fnames=None):
        self.exe('git checkout %s' % branch, clone_dir)

        if not fnames:
            # If no file names are passed, create a test file
            fname = create_random_str()
            data = 'data'
            file(os.path.join(clone_dir, fname), 'w').write(data)
            fnames = [fname]

        self.git_add(clone_dir, fnames)
        if commit_msg:
            author = '%s <%s>' % (commit_author,
                                  config.USERS[commit_author]['email']) \
                     if commit_author else self.author
            self.exe("git commit --author '%s' -m '%s'" %
                     (author, commit_msg), clone_dir)
        else:
            # If commit message is None, we need to ammend the old commit
            self.exe("git reset --soft HEAD^", clone_dir)
            self.exe("git commit -C ORIG_HEAD", clone_dir)

        sha = open("%s/.git/refs/heads/%s" % (clone_dir, branch)).read()
        self.exe('git review -v', clone_dir)
        return sha

    def get_branches(self, clone_dir, include_remotes=False):
        cmd = 'git branch'
        if include_remotes:
            cmd += ' --remote'
        out = self.exe(cmd, clone_dir)
        return out.split()


class JobUtils(Tool):
    def __init__(self):
        Tool.__init__(self)
        self.cookies = {'auth_pubtkt': get_cookie(config.USER_1,
                                                  config.USER_1_PASSWORD)}

    def wait_for_config_update(self, revision, return_result=False):
        zuul3 = os.environ.get("SF_ZUUL_EXECUTOR", "1") != "0"
        if zuul3:
            return self.wait_for_config_update_zuul3(revision, return_result)
        else:
            return self.wait_for_config_update_zuul2(revision, return_result)

    def wait_for_config_update_zuul2(self, revision, return_result=False):
        params = deepcopy(config.ZUUL_MYSQL)
        params['revision'] = revision
        out = None
        cmd = ["/usr/bin/mysql", "--host=%(host)s" % params,
               "--user=%(user)s" % params, "--password=%(password)s" % params,
               "zuul", "-N", "-B",
               """--execute="select result from zuul_build where """
               """buildset_id in (select id from zuul_buildset where """
               """ref = '%(revision)s') and """
               """job_name = 'config-update'" """ % params]
        try:
            for retry in range(240):
                out, err = ssh_run_cmd(config.SERVICE_PRIV_KEY_PATH,
                                       "root",
                                       'managesf.' + config.GATEWAY_HOST,
                                       cmd, verbose=False)
                if "SUCCESS" in out:
                    return out
                else:
                    logger.info(out)
                time.sleep(1)
        except Exception as e:
            logger.exception('Retry%d: command "%s": resulted in error %s' % (
                retry, cmd % params, e))
        return "FAILED"

    def wait_for_config_update_zuul3(self, revision, return_result=False):
        base_url = "%s/zuul/local/builds" % config.GATEWAY_URL
        # TODO remove after 3.0 release
        r = requests.head(base_url)
        if r.status_code == 404:
            base_url = "%s/zuul3/local/builds.json" % config.GATEWAY_URL
        job_url = "?job_name=config-update&newrev=%s" % revision
        logger.debug(
            "Waiting for config-update using %s" % (base_url + job_url))
        r = None
        try:
            for retry in range(240):
                r = requests.get(base_url + job_url)
                if r.ok:
                    j = r.json()
                    logger.debug("Got build results: %s" % j)
                    result = None
                    if len(j):
                        result = j[0]['result']
                    if return_result and result:
                        return result
                    return
                time.sleep(1)
        except:
            logger.exception("Retry%d: Couldn't get %s: %s" % (
                retry, base_url + job_url, r.text))
            if not r.ok:
                logger.error("Response was %s : %s" % (r, r.text))
        return "FAILED"


class ResourcesUtils():

    def __init__(self, yaml=None):
        default_yaml = """resources:
  acls:
    %(name)s-acl:
      file: |
        [access "refs/*"]
          read = group %(name)s-core
          owner = group %(name)s-ptl
        [access "refs/heads/*"]
          label-Verified = -2..+2 group %(name)s-ptl
          label-Code-Review = -2..+2 group %(name)s-core
          label-Workflow = -1..+1 group %(name)s-core
          submit = group %(name)s-ptl
          read = group %(name)s-core
        [access "refs/meta/config"]
          read = group %(name)s-core
        [receive]
          requireChangeId = true
        [submit]
          mergeContent = false
          action = rebase if necessary
      groups:
      - %(name)s-core
      - %(name)s-ptl
  groups:
    %(name)s-core:
      description: Core developers for project %(name)s
      members:
        - admin@%(fqdn)s
    %(name)s-ptl:
      description: Project team lead for project %(name)s
      members:
        - admin@%(fqdn)s
  repos:
    %(name)s:
      acl: %(name)s-acl
      description: Code repository for %(name)s
  projects:
    %(name)s:
      description: Project %(name)s
      issue-tracker: SFStoryboard
      source-repositories:
        - %(name)s
"""
        self.ju = JobUtils()
        self.url = "ssh://admin@%s:29418/%s" % (config.GATEWAY_HOST, 'config')
        self.ggu = GerritGitUtils(
            'admin',
            set_private_key(config.USERS['admin']["privkey"]),
            config.USERS['admin']['email'])
        self.yaml = yaml or default_yaml

    def get_resources(self):
        r = requests.get(config.MANAGESF_API + 'v2/resources/')
        return r.json()

    def _direct_push(self, cdir, msg):
        self.ggu.add_commit_for_all_new_additions(cdir, msg)
        change_sha = self.ggu.direct_push_branch(cdir, 'master')
        config_update_log = self.ju.wait_for_config_update(change_sha)
        c1 = "SUCCESS" in config_update_log
        c2 = len(
            re.findall(
                'managesf\..*failed=0', config_update_log)) == 1
        assert c1 or c2

    def create_resources(self, name, data):
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        rfile = os.path.join(cdir, 'resources', name + '.yaml')
        yaml.dump(data, file(rfile, "w"), default_flow_style=False)
        self._direct_push(cdir, 'Add resources %s' % name)

    def create_repo(self, name):
        yaml = self.yaml % {'name': name, 'fqdn': config.GATEWAY_HOST}
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        file(os.path.join(cdir, 'resources', name + '.yaml'), 'w').write(yaml)
        self._direct_push(cdir, 'Add project %s' % name)

    def delete_repo(self, name):
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        os.unlink(os.path.join(cdir, 'resources', name + '.yaml'))
        self._direct_push(cdir, 'Del project %s' % name)

    def _direct_apply_call(self, prev, new):
        data = {'prev': prev, 'new': new}
        cookie = get_cookie(config.SF_SERVICE_USER,
                            config.SF_SERVICE_USER_PASSWORD)
        cookie = {"auth_pubtkt": cookie}
        r = requests.put(config.MANAGESF_API + 'v2/resources/',
                         cookies=cookie,
                         json=data)
        assert r.status_code < 300
        return r.json()

    def direct_create_repo(self, name):
        wanted_state_yaml = self.yaml % {
            'name': name, 'fqdn': config.GATEWAY_HOST}
        previous_state_yaml = yaml.dump({'resources': {}})
        self._direct_apply_call(previous_state_yaml,
                                wanted_state_yaml)

    def direct_delete_repo(self, name):
        previous_state_yaml = self.yaml % {
            'name': name, 'fqdn': config.GATEWAY_HOST}
        wanted_state_yaml = yaml.dump({'resources': {}})
        self._direct_apply_call(previous_state_yaml,
                                wanted_state_yaml)
