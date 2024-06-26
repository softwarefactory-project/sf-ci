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

import json
import jwt
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
import urllib.parse
import uuid
import yaml

import logging
import pkg_resources

from requests.auth import HTTPBasicAuth

from distutils.version import StrictVersion
from subprocess import Popen, PIPE

import config


logging.getLogger("requests").setLevel(logging.WARNING)
logging.captureWarnings(True)
logging.basicConfig(
    format="%(asctime)s: %(levelname)-5.5s %(name)s - %(message)s",
    level=logging.DEBUG)
logger = logging.getLogger(__name__)

# for easier imports
skipIf = unittest.skipIf
skip = unittest.skip

services = config.groupvars['roles'].keys()


def cmp_version(v1, v2):
    return StrictVersion(v1) < StrictVersion(v2)


def is_on_master():
    return config.groupvars['sf_version'] == 'master'


def is_sf_version_over(version):
    return (
        is_on_master()
        or cmp_version(config.groupvars['sf_version'], version)
    )


def is_present(service):
    return service in services


def has_issue_tracker():
    return set(config.ISSUE_TRACKERS) & set(services)


def skipIfStrInFile(check_str, path):
    return skipIf(check_str in open(path).read(),
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


def skipIfSoftwareFactoryVersionLowerThan(version):
    return skipIf(not is_sf_version_over(version),
                  'This version of SF is lower than %s' % version)


def skipReason(reason):
    return skip("%s" % reason)


def get_module_version(module):
    m = module
    if not isinstance(m, str):
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
    open(priv_key_path, 'w').write(priv_key)
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


def get_auth_params(username, password):
    params = {'cookies': {},
              'headers': {}}
    if not config.KC_AUTH:
        params['cookies']['auth_pubtkt'] = get_cookie(username,
                                                      password)
    else:
        params['headers']['Authorization'] = 'Bearer %s' % get_jwt(username,
                                                                   password)
    return params


def get_jwt(username, password, client=None):
    token_endpoint = "auth/realms/sf/protocol/openid-connect/token"
    url = "%(auth_url)s/%(endpoint)s" % {'auth_url': config.GATEWAY_URL,
                                         'endpoint': token_endpoint}
    resp = requests.post(url, data={'client_id': client or 'managesf',
                                    'grant_type': 'password',
                                    'username': username,
                                    'password': password})
    if resp.json().get('access_token'):
        return resp.json().get('access_token')
    else:
        raise Exception(
            'could not get token for %s: %s' % (username, resp.text))


def get_decoded_jwt(username, password):
    token = get_jwt(username, password)
    return jwt.decode(token, options={"verify_signature": False})


def call_endpoint_with_bearer_auth(callback,
                                   endpointUrl="",
                                   token="",
                                   **kwargs):
    bearer_header = f"Bearer {token}"
    _kwargs = dict(kwargs)
    if 'headers' in _kwargs:
        _kwargs['headers']['Authorization'] = bearer_header
    else:
        _kwargs['headers'] = {'Authorization': bearer_header}
    return callback(endpointUrl, **_kwargs)


def _get_user_attribute(username, password, attribute):
    token = get_jwt('admin', config.USERS['admin']['password'])
    user_token = get_decoded_jwt(username, password)
    endpoint = f"auth/admin/realms/sf/users/{user_token['sub']}/{attribute}"
    urlUserAttribute = f"{config.GATEWAY_URL}/{endpoint}"
    return call_endpoint_with_bearer_auth(
        requests.get, urlUserAttribute, token
    )


def get_user_groups(username, password):
    return _get_user_attribute(username, password, "groups")


def get_user_roles(username, password):
    return _get_user_attribute(username, password, "roles")


def get_cookie(username, password):
    url = "%(auth_url)s/auth/login" % {'auth_url': config.GATEWAY_URL}
    resp = requests.post(url, params={'username': username,
                                      'password': password,
                                      'back': '/'},
                         allow_redirects=False)
    return resp.cookies.get('auth_pubtkt', '')


def get_gerrit_utils(user):
    # TODO admin user should not be a special case
    if user == config.USER_1:
        http_password = config.USERS[user]['api_key']
    else:
        http_password = config.USERS[user]['password']
    return GerritClient(
        config.GATEWAY_URL + "/r/a",
        auth=HTTPBasicAuth(user, http_password))


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
        ocwd = os.getcwd()
        output = ''
        if cwd:
            os.chdir(cwd)
        try:
            self.env['LC_ALL'] = 'en_US.UTF-8'
            output = subprocess.check_output(
                shlex.split(cmd), stderr=subprocess.STDOUT,
                env=self.env).decode('utf-8')
            if output:
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


class KeycloakUtils():
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.admin_user = config.ADMIN_USER
        self.admin_password = config.USERS[config.ADMIN_USER]['password']

    def create_user(self, username, password, email):
        auth_params = get_auth_params(self.admin_user, self.admin_password)
        userInfo = {"username": username,
                    "email": email,
                    "credentials": [
                        {"type": "password",
                         "value": password}],
                    "enabled": True}
        url = self.url + '/auth/admin/realms/sf/users'
        resp = requests.post(url, json=userInfo, **auth_params)
        if resp.ok:
            location = resp.headers['Location']
            return requests.get(location, **auth_params).json()
        else:
            resp.raise_for_status()

    def roles(self):
        auth_params = get_auth_params(self.admin_user, self.admin_password)
        url = self.url + '/auth/admin/realms/sf/roles'
        return requests.get(url, **auth_params).json()

    def add_role_to_user(self, userid, role):
        auth_params = get_auth_params(self.admin_user, self.admin_password)
        url = self.url + '/auth/admin/realms/sf/users/' +\
            '%s/role-mappings/realm' % userid
        payload = [
            {
                'clientRole': False,
                'composite': False,
                'containerId': role['containerId'],
                'id': role['id'],
                'name': role['name'],
            }
        ]
        resp = requests.post(url, json=payload, **auth_params)
        return resp.ok


class NotFound(Exception):
    pass


class ZuulClient():
    def __init__(self, url, token):
        self.base_url = url.strip('/')
        self.token = token

    @property
    def headers(self):
        return {"Authorization": "bearer " + self.token}

    def authorizations(self, tenant):
        url = self.base_url + f'/tenant/{tenant}/authorizations'
        return requests.get(url, headers=self.headers)

    def tenants(self):
        url = self.base_url + '/tenants'
        tenants = requests.get(url).json()
        return [t['name'] for t in tenants]


def get_zuul_client(username, password):
    z_token = get_jwt(
        username, password, 'zuul'
    )
    z_url = config.GATEWAY_URL + "/zuul/api"
    return ZuulClient(z_url, z_token)


class GerritClient:
    log = logging.getLogger("GerritClient")

    def __init__(self, url, auth):
        self.url = url
        self.auth = auth
        # TEMP: fix this usage in test_resources_workflow when 3.1 is released
        self.g = self

    def decode(self, resp):
        if not resp.text:
            return None
        try:
            return json.loads(resp.text[4:])
        except ValueError:
            self.log.error("Couldn't decode: [%s]" % resp.text)

    def quote(self, toquote):
        return urllib.parse.quote_plus(toquote)

    def request(self, method, url, json_data=None, raw_data=None):
        resp = requests.request(
            method, url, json=json_data, data=raw_data, auth=self.auth)
        self.log.debug("%6s | %s (%s) -> %s" % (method, url, json_data, resp))
        return resp

    def get(self, url):
        # TEMP: fix this usage in test_resources_workflow when 3.1 is released
        if url[0] == "/":
            url = url[1:]
        resp = self.request("get", os.path.join(self.url, url))
        if resp.status_code == 404:
            raise NotFound()
        if not resp.ok:
            raise RuntimeError(resp.text)
        return self.decode(resp)

    def post(self, url, json_data=None, raw_data=None):
        resp = self.request(
            "post", os.path.join(self.url, url), json_data, raw_data)
        if resp.status_code >= 400:
            return None
        return self.decode(resp)

    def put(self, url, json_data=None):
        resp = self.request(
            "put", os.path.join(self.url, url), json_data)
        if resp.status_code >= 400:
            return None
        return self.decode(resp)

    def delete(self, url):
        resp = self.request("delete", os.path.join(self.url, url))
        if not resp.ok:
            raise RuntimeError("Couldn't delete %s" % url)

    # Account
    def create_account(self, username, password, email):
        account = {
            "email": email,
            "http_password": password}
        return self.put("accounts/%s" % self.quote(username), account)

    def get_account(self, username):
        return self.get('accounts/%s' % self.quote(username))

    def is_account_active(self, username):
        try:
            if self.get("accounts/%s/active" % self.quote(username)) == "ok":
                return True
        except NotFound:
            pass
        return False

    # Changes
    def get_info(self, change_number):
        return self.get("changes/%d/detail" % change_number)

    def get_vote(self, change_number, label, username="jenkins"):
        info = self.get_info(change_number)
        if not info:
            return None
        for vote in info["labels"][label].get("all", []):
            if vote.get("username") == username:
                return vote.get("value")

    def wait_for_verify(self, change_number, users=None, timeout=60):
        # make sure users is a list
        if not users:
            users = ['jenkins']
        if isinstance(users, str):
            users = [users]
        for retry in range(timeout):
            votes = [self.get_vote(change_number,
                                   "Verified", user) for user in users]
            if any(votes):
                return [vote for vote in votes if vote][0]
            time.sleep(1)
        msg = "%s didn't vote on %d" % (users, change_number)
        logger.error(msg)
        raise RuntimeError(msg)

    def get_change_number(self, commit):
        try:
            changes = self.get("changes/?q=commit:%s" % commit)
        except Exception:
            self.log.exception("Couldn't get changes for commit %s" % (commit))
            raise
        if len(changes) != 1:
            self.log.warning("Multiple change match commit %s" % commit)
        return changes[0]['_number']

    def get_my_changes_for_project(self, project):
        try:
            changes = self.get('changes/?q=owner:self+project:%s' % project)
            return [c['change_id'] for c in changes]
        except Exception:
            self.log.exception("Couldn't get changes for project %s" % project)
            raise

    def get_labels_list_for_change(self, change):
        try:
            ret = self.get('changes/%s/?o=LABELS' % change)
            return ret['labels']
        except Exception:
            self.log.exception("Couldn't get labels for %s" % change)
            raise

    def get_reviewers(self, change):
        try:
            ret = self.get('changes/%s/reviewers' % change)
            return [r['username'] for r in ret]
        except Exception:
            self.log.exception("Couldn't get reviewers of %s" % change)
            raise

    def get_change(self, change, o="CURRENT_REVISION"):
        return self.get('changes/%s/?o=%s' % (change, o))

    def submit_change_note(self, change, revision, label, rate):
        try:
            self.post('changes/%s/revisions/%s/review' % (change, revision),
                      {"labels": {label: int(rate)}})
        except Exception:
            self.log.exception("Couldn't submit vote on %s" % change)
            raise

    # TODO: remove unused submit_patch parameter in test_gerrit
    def submit_patch(self, change, _):
        try:
            ret = self.post('changes/%s/submit' % change,
                            {"wait_for_merge": True})
            if ret and ret['status'] == 'MERGED':
                return True
            else:
                return False
        except Exception:
            self.log.exception("Couldn't submit patch %s" % change)
            raise

    # Pub keys
    def del_pubkey(self, index, user='self'):
        self.delete('accounts/%s/sshkeys/%s' % (user, index))

    def add_pubkey(self, pubkey, user='self'):
        response = self.post('accounts/%s/sshkeys' % user, raw_data=pubkey)
        self.log.info(response)
        return response['seq']

    # Groups
    def get_group_id(self, name):
        try:
            name = self.quote(name)
            gid = self.get('groups/%s/detail' % name)['id']
            return urllib.parse.unquote_plus(gid)
        except NotFound:
            return False
        except Exception:
            self.log.exception("Couldn't get group id %s" % name)
            raise

    def get_group_members(self, name):
        try:
            name = self.quote(name)
            return self.get('groups/%s/members/' % name)
        except Exception:
            self.log.exception("Couldn't get group members %s" % name)
            raise

    # Projects
    def project_exists(self, name):
        try:
            name = self.quote(name)
            self.get('projects/%s' % name)
            return True
        except NotFound:
            return False
        except Exception:
            self.log.exception("Couldn't check project %s" % name)
            raise

    # Config
    def list_plugins(self):
        return self.get('plugins/?all')


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
        open(wrapper_path, 'w').write(ssh_wrapper)
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
        self.exe(
            "ssh-agent bash -c 'ssh-add %s; /usr/local/bin/git-review -s'" %
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
            open(os.path.join(clone_dir, 'testfile'), 'w').write('data')
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
            self.exe('/usr/local/bin/git-review -v', clone_dir)
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
        self.exe('/usr/local/bin/git-review', clone_dir)
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
            open(os.path.join(clone_dir, fname), 'w').write(data)
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
        self.exe('/usr/local/bin/git-review -v', clone_dir)
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

    def wait_for_config_update(self, revision, return_result=False):
        base_url = "%s/zuul/api/tenant/local/builds" % config.GATEWAY_URL
        # Remove this when 3.0 is updated with last zuul package
        r = requests.get(base_url)
        if r.status_code == 404:
            base_url = "%s/zuul/local/builds" % config.GATEWAY_URL
        # TODO when zuul > 4.6, use the "complete=1" param
        # to ensure we only get completed builds.
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
                    job_log_url = None
                    result = None
                    if len(j):
                        job_log_url = "%s/job-output.txt.gz" % (
                            j[0]['log_url'])
                        result = j[0]['result']
                    if return_result:
                        if result is not None:
                            return result
                    if result and job_log_url:
                        return requests.get(job_log_url).text
                    logger.debug("Build was added to SQL reporter, "
                                 "but has not completed yet")
                time.sleep(1)
        except Exception:
            logger.exception("Retry%d: Couldn't get %s: %s" % (
                retry, base_url + job_url, r.text))
            if not r.ok:
                logger.error("Response was %s : %s" % (r, r.text))
        return "FAILED"


class ResourcesUtils(Tool):

    def __init__(self, yaml=None):
        Tool.__init__(self)
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
                r'managesf\..*failed=0', config_update_log)) == 1
        assert c1 or c2

    def create_resources(self, name, data):
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        rfile = os.path.join(cdir, 'resources', name + '.yaml')
        yaml.dump(data, open(rfile, "w"), default_flow_style=False)
        self._direct_push(cdir, 'Add resources %s' % name)

    def create_repo(self, name):
        yaml = self.yaml % {'name': name, 'fqdn': config.GATEWAY_HOST}
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        open(os.path.join(cdir, 'resources', name + '.yaml'), 'w').write(yaml)
        self._direct_push(cdir, 'Add project %s' % name)

    def delete_repo(self, name):
        cdir = self.ggu.clone(self.url, 'config', config_review=False)
        os.unlink(os.path.join(cdir, 'resources', name + '.yaml'))
        self._direct_push(cdir, 'Del project %s' % name)

    def direct_create_repo(self, name):
        wanted_state_yaml = self.yaml % {
            'name': name, 'fqdn': config.GATEWAY_HOST}
        previous_state_yaml = yaml.dump({'resources': {}})
        open("/tmp/prev.yaml", "w").write(previous_state_yaml)
        open("/tmp/new.yaml", "w").write(wanted_state_yaml)
        cmd = "sudo /usr/local/bin/managesf-resources "
        cmd += "direct-apply --prev-yaml /tmp/prev.yaml "
        cmd += "--new-yaml /tmp/new.yaml"
        self.exe(cmd)

    def direct_delete_repo(self, name):
        previous_state_yaml = self.yaml % {
            'name': name, 'fqdn': config.GATEWAY_HOST}
        wanted_state_yaml = yaml.dump({'resources': {}})
        open("/tmp/prev.yaml", "w").write(previous_state_yaml)
        open("/tmp/new.yaml", "w").write(wanted_state_yaml)
        cmd = "sudo /usr/local/bin/managesf-resources "
        cmd += "direct-apply --prev-yaml /tmp/prev.yaml "
        cmd += "--new-yaml /tmp/new.yaml"
        self.exe(cmd)
