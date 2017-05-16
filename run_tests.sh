#!/bin/bash

set -ex

# On slave node a Jenkins user is already created with login shell
# To avoid further issue reset it to /sbin/nologin
sudo sed -i '/^jenkins/ s#/sbin/sh#/sbin/nologin#' /etc/passwd

sudo ansible-playbook sf-init.yaml
sudo ansible-playbook sf-install.yaml
sudo ansible-playbook sf-setup.yaml
sudo ansible-playbook sf-serverspec.yaml
