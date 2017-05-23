#!/bin/bash

set -ex

test -f ~/.local/bin/ara 2> /dev/null || {
	sudo yum install -y python-pip
	pip install --user 'ara==0.12.4'
}
test -d /usr/lib/python2.7/site-packages/nose_htmloutput || {
	pip install nose-htmloutput
}

rm -Rf ~/.ara/
export ara_location=$(python -c "import os,ara; print(os.path.dirname(ara.__file__))")
export ANSIBLE_CALLBACK_PLUGINS=$ara_location/plugins/callbacks
export ANSIBLE_ACTION_PLUGINS=$ara_location/plugins/actions
export ANSIBLE_LIBRARY=$ara_location/plugins/modules

# On slave node a Jenkins user is already created with login shell
# To avoid further with sf-jenkins setup task issue reset it to /sbin/nologin
sed -i '/^jenkins/ s#/sbin/sh#/sbin/nologin#' /etc/passwd

USER=${SUDO_USER:-$USER}

# Prepare artifacts directory
WORKSPACE=${WORKSPACE:-/root}
mkdir -p ${WORKSPACE}/artifacts

function terminate {
    # Restore a login shell to let us connect to the slave for debug
    sed -i '/^jenkins/ s#/sbin/nologin#/bin/bash#' /etc/passwd
    ansible-playbook /var/lib/software-factory/ansible/get_logs.yml
    # Prepare artifacts for zuul_swift_upload
    rsync -a --no-links /root/sf-logs/ ${WORKSPACE}/artifacts
    pushd ${WORKSPACE}/artifacts
    	rm -Rf html
    	~/.local/bin/ara generate html
    popd
    tar -czf ${WORKSPACE}/artifacts.tgz ${WORKSPACE}/artifacts
    mv ${WORKSPACE}/artifacts.tgz ${WORKSPACE}/artifacts/
    chown -R ${USER}:${USER} ${WORKSPACE}/artifacts
}

trap 'terminate' ERR

function run_functional_tests {
    ansible-playbook sf-prepare-functional-tests.yaml
    chown -R ${SUDO_USER} /var/lib/software-factory/bootstrap-data
    ./create_ns.sh nosetests --with-html --html-file=nose_results.html -sv tests/functional
    mv nose_results.html ${WORKSPACE}/artifacts/
}

ansible-playbook sf-init.yaml
ansible-playbook /var/lib/software-factory/ansible/sf_install.yml
ansible-playbook /var/lib/software-factory/ansible/sf_setup.yml
ansible-playbook sf-serverspec.yaml
ansible-playbook health-check/sf-health-check.yaml
run_functional_tests

terminate
