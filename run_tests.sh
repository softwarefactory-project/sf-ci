#!/bin/bash

set -ex

# On slave node a Jenkins user is already created with login shell
# To avoid further with sf-jenkins setup task issue reset it to /sbin/nologin
sed -i '/^jenkins/ s#/sbin/sh#/sbin/nologin#' /etc/passwd

# Prepare artifacts directory
WORKSPACE=${WORKSPACE:-/root}
mkdir -p ${WORKSPACE}/artifacts

function terminate {
    # Restore a login shell to let us connect to the slave for debug
    sed -i '/^jenkins/ s#/sbin/nologin#/bin/bash#' /etc/passwd
    ansible-playbook /var/lib/software-factory/ansible/get_logs.yml 
    rsync -a /root/sf-logs/ ${WORKSPACE}/artifacts
    # to be moved in a DIB element
    yum install -y zuul-swift-upload
}

trap 'terminate' ERR

ansible-playbook sf-init.yaml
ansible-playbook /var/lib/software-factory/ansible/sf_install.yml
ansible-playbook /var/lib/software-factory/ansible/sf_setup.yml
ansible-playbook sf-serverspec.yaml
# Bellow call will be refactored when health-check will be migrated in the sf-ci repo
ansible-playbook sf-health-check.yaml
ansible-playbook /tmp/health-check/zuul.yaml

terminate
