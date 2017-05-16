#!/bin/bash

set -ex

ansible-playbook sf-init.yaml
sudo chmod 755 /var/lib/software-factory/ansible
ansible-playbook sf-install.yaml
ansible-playbook sf-setup.yaml
ansible-playbook sf-serverspec.yaml
