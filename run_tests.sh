#!/bin/bash

set -ex

# On slave node a Jenkins user is already created with login shell
# To avoid further with sf-jenkins setup task issue reset it to /sbin/nologin
sudo sed -i '/^jenkins/ s#/sbin/sh#/sbin/nologin#' /etc/passwd

set_jenkins_shell() {
    # Restore a login shell to let us connect to the slave for debug
    sudo sed -i '/^jenkins/ s#/sbin/nologin#/bin/bash#' /etc/passwd
}

trap 'set_jenkins_shell' ERR

sudo ansible-playbook sf-init.yaml
sudo ansible-playbook sf-install.yaml
sudo ansible-playbook sf-setup.yaml
sudo ansible-playbook sf-serverspec.yaml
# Bellow call will be refactored when health-check will be migrated in the sf-ci repo
sudo ansible-playbook sf-health-check.yaml
sudo ansible-playbook /tmp/health-check/zuul.yaml
