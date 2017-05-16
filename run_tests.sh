#!/bin/bash

set -ex

sudo ansible-playbook sf-init.yaml
sudo ansible-playbook sf-install.yaml
sudo ansible-playbook sf-setup.yaml
sudo ansible-playbook sf-serverspec.yaml
