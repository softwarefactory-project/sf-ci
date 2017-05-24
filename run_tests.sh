#!/bin/bash

set -Ex

TEST_TYPE="$1"
ARCH="$2"

rm -Rf ~/.ara/
export ara_location=$(python -c "import os,ara; print(os.path.dirname(ara.__file__))")
export ANSIBLE_CALLBACK_PLUGINS=$ara_location/plugins/callbacks
export ANSIBLE_ACTION_PLUGINS=$ara_location/plugins/actions
export ANSIBLE_LIBRARY=$ara_location/plugins/modules

# On slave node a Jenkins user is already created with login shell
# To avoid further with sf-jenkins setup task issue reset it to /sbin/nologin
sed -i '/^jenkins/ s#:[^:]*$#:/sbin/nologin#' /etc/passwd

USER=${SUDO_USER:-$USER}

# Prepare artifacts directory
WORKSPACE=${WORKSPACE:-/root}
ARTIFACTS=$(realpath ${WORKSPACE}/artifacts)
mkdir -p ${ARTIFACTS}

function terminate {
    # Restore a login shell to let us connect to the slave for debug
    sed -i '/^jenkins/ s#:[^:]*$#:/bin/bash#' /etc/passwd
    ansible-playbook /var/lib/software-factory/ansible/get_logs.yml
    # Prepare artifacts for zuul_swift_upload
    rsync -a --no-links /root/sf-logs/ ${ARTIFACTS}/
    pushd ${ARTIFACTS}
        rm -Rf html
        ara generate html
    popd
    cp -Rv /etc/yum.repos.d/ ${ARTIFACTS}
    rsync -anvi /etc/yum.repos.d/ ${ARTIFACTS}/yum.repos.d/ --exclude "CentOS-*.repo"
    tar -czf ${ARTIFACTS}.tgz ${ARTIFACTS}
    mv ${ARTIFACTS}.tgz ${ARTIFACTS}/
    chown -R ${USER}:${USER} ${ARTIFACTS}
    [ "$1" == "END" ] && exit 0 || exit 1
}

trap 'terminate' ERR

function run_functional_tests() {
    ansible-playbook sf-prepare-functional-tests.yaml
    chown -R ${SUDO_USER} /var/lib/software-factory/bootstrap-data
    ./create_ns.sh nosetests --with-html --html-file=nose_results.html -sv tests/functional
    mv nose_results.html ${ARTIFACTS}/
}

# TODO: make this a parameter
if [ "${TEST_TYPE}" == "upgrade" ]; then
    VERSION="2.5.0"

    ansible-playbook -e "sf_arch=${ARCH} sf_version=${VERSION}" sf-init-stable.yaml
else
    ansible-playbook -e "sf_arch=${ARCH}" sf-init-master.yaml
fi


# Deploy
ansible-playbook /var/lib/software-factory/ansible/sf_install.yml
ansible-playbook /var/lib/software-factory/ansible/sf_setup.yml

# TODO: run provisioner

if [ "${TEST_TYPE}" == "upgrade" ]; then
    ansible-playbook sf-upgrade.yaml
    ansible-playbook /var/lib/software-factory/ansible/sf_upgrade.yml
    ansible-playbook /var/lib/software-factory/ansible/sf_install.yml
    ansible-playbook /var/lib/software-factory/ansible/sf_setup.yml

    rpm -qa | sort > package_upgraded
    diff /var/lib/software-factory/package_installed package_upgraded || true
    # TODO: run provisioner check
fi

ansible-playbook sf-serverspec.yaml
ansible-playbook health-check/sf-health-check.yaml
run_functional_tests

if [ "${TEST_TYPE}" == "functional" ]; then
    # TODO: erase deployment and recover backup test
    echo pass
fi

terminate 'END'
