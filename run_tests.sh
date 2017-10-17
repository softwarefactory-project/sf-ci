#!/bin/bash

set -Ex

# TODO: remove quick fix bellow
sudo yum update -y ansible
# TODO: To be removed when are bump merged and images rebuilt
sudo yum install -y https://softwarefactory-project.io/logs/97/9997/1/check/sf-rpm-build/Zc3a7e638f27642cd853e6c94ce133f41/zuul-rpm-build/ara-0.14.4-1.el7.noarch.rpm
sudo yum update -y ara

# Remove ZUUL_* environment variables. We do not need them to be present
# after that statement.
while read var; do unset $var; done < <(env | egrep "^ZUUL_.*" | awk -F= '{ print $1}')

TEST_TYPE="${1:-functional}"
ARCH="${2:-minimal}"
FUNC_TEST_CASE="${3:-tests/functional}"
WORKSPACE=${WORKSPACE:-$(realpath $(pwd)/..)}
ARTIFACTS=${WORKSPACE}/artifacts
VERSION="${SF_VERSION:-master}"
USER=${SUDO_USER:-${USER}}
LOCAL_REPO_PATH="${LOCAL_REPO_PATH:-}"

rm -Rf ~/.ara/ ${ARTIFACTS}/

# Quick-fix for exception bellow happening when ara is activated...:
# DistributionNotFound: The 'jinja2<2.9' distribution was not found and is required by ansible
sudo sed -i 's/^jinja2.*//' /usr/lib/python2.7/site-packages/ansible*.egg-info/requires.txt
sudo sed -i 's/^MarkupSafe.*//' /usr/lib/python2.7/site-packages/Jinja2-*.egg-info/requires.txt

export ARA_LOG_FILE=
export ara_location=$(python -c "import os,ara; print(os.path.dirname(ara.__file__))")
export ANSIBLE_CALLBACK_PLUGINS=$ara_location/plugins/callbacks
export ANSIBLE_ACTION_PLUGINS=$ara_location/plugins/actions
export ANSIBLE_LIBRARY=$ara_location/plugins/modules

function terminate {
    if which ara &> /dev/null; then
        mkdir -p ${ARTIFACTS}
        pushd ${ARTIFACTS}
            rm -Rf ara-report
            ara generate html ara-report
        popd
    fi
    sudo chown -R ${USER}:${USER} ${ARTIFACTS}
    [ "$1" == "END" ] && exit 0 || exit 1
}

trap 'terminate' ERR
ansible-playbook -M modules/                     \
         -i 'localhost,'                         \
         -e @playbooks/group_vars/all.yaml       \
         -e sf_user=${USER}                      \
         -e workspace=${WORKSPACE}               \
         -e local_repo_path=${LOCAL_REPO_PATH}   \
         -e sf_ci=$(pwd)                         \
         -e sf_arch=${ARCH}                      \
         -e sf_version=${VERSION}                \
         -e func_test_case=${FUNC_TEST_CASE}     \
         ${EXTRA_VARS}                           \
         playbooks/${TEST_TYPE}.yml

terminate 'END'
