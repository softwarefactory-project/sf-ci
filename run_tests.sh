#!/bin/bash

set -Ex

TEST_TYPE="${1:-functional}"
ARCH="${2:-minimal}"
FUNC_TEST_CASE="${3:-tests/functional}"
WORKSPACE=${WORKSPACE:-$(realpath $(pwd)/..)}
ARTIFACTS=${WORKSPACE}/artifacts
VERSION="${SF_VERSION:-master}"
USER=${SUDO_USER:-${USER}}

rm -Rf ~/.ara/ ${ARTIFACTS}/

# Quick-fix for exception bellow happening when ara is activated...:
# DistributionNotFound: The 'jinja2<2.9' distribution was not found and is required by ansible
sudo sed -i 's/^jinja2.*//' /usr/lib/python2.7/site-packages/ansible*.egg-info/requires.txt
sudo sed -i 's/^MarkupSafe.*//' /usr/lib/python2.7/site-packages/Jinja2-*.egg-info/requires.txt

export ara_location=$(python -c "import os,ara; print(os.path.dirname(ara.__file__))")
export ANSIBLE_CALLBACK_PLUGINS=$ara_location/plugins/callbacks
export ANSIBLE_ACTION_PLUGINS=$ara_location/plugins/actions
export ANSIBLE_LIBRARY=$ara_location/plugins/modules

function terminate {
    pushd ${ARTIFACTS}
        rm -Rf ara-report
        ara generate html ara-report
    popd
    sudo chown -R ${USER}:${USER} ${ARTIFACTS}
    [ "$1" == "END" ] && exit 0 || exit 1
}

if [ "${TEST_TYPE}" == "upgrade" ]; then
    VERSION="2.5.0"
fi

trap 'terminate' ERR
ansible-playbook -e "sf_user=${USER} workspace=${WORKSPACE} sf_ci=$(pwd) sf_arch=${ARCH} sf_version=${VERSION} func_test_case=${FUNC_TEST_CASE}" playbooks/${TEST_TYPE}.yml

terminate 'END'
