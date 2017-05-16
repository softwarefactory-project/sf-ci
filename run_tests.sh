#!/bin/bash

set -ex

ansible-playbook sf-init.yaml
ansible-playbook sf-install.yaml
ansible-playbook sf-setup.yaml
ansible-playbook sf-serverspec.yaml
