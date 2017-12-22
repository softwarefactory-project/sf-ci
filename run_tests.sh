#!/bin/bash

set -Ex

# TODO: remove when dib-centos-7 is build with sf-2.7
PIKE="http://cbs.centos.org/repos/cloud7-openstack-pike-release/x86_64/os/"
SF="https://softwarefactory-project.io/kojifiles/repos/sf-2.7-el7-release/"
sudo yum install -y "${PIKE}/Packages/python2-subunit-1.2.0-14.el7.noarch.rpm"
sudo yum install -y "${SF}/Mash/ara-0.14.4-1.el7.noarch.rpm"

# Remove ZUUL_* environment variables. We do not need them to be present
# after that statement.
while read var; do
    unset $var
done < <(env | egrep "^ZUUL_.*" | awk -F= '{ print $1}')

TEST_TYPE="${1:-functional}"
ARCH="${2:-minimal}"
FUNC_TEST_CASE="${3:-tests/functional}"
WORKSPACE=${WORKSPACE:-$(realpath $(pwd)/..)}
ARTIFACTS=${WORKSPACE}/artifacts
VERSION="${SF_VERSION:-master}"
USER=${SUDO_USER:-${USER}}
LOCAL_REPO_PATH="${LOCAL_REPO_PATH:-}"

rm -Rf ~/.ara/ ${ARTIFACTS}/

export ARA_LOG_FILE=
export ara_location=$(
    python -c "import os,ara; print(os.path.dirname(ara.__file__))")
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
ansible-playbook -M modules/                             \
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
