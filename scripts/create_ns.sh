#!/bin/sh
# Simple netns creation

if [ -z "$SUDO_COMMAND" ]; then
    echo "$0: run with sudo"
    exit 1
fi

if ! ip netns | grep local-test -q; then
    ip netns add local-test
    ip link add vlocal0 type veth peer name vlocal1
    ip link set vlocal0 up
    ip addr add 192.168.42.1/30 dev vlocal0

    ip link set vlocal1 netns local-test up
    ip netns exec local-test ip addr add 192.168.42.2/30 dev vlocal1
    ip netns exec local-test ip route add default via 192.168.42.1
fi

if [ "$1" == "stop" ]; then
    ip link delete vlocal0
        ip netns delete local-test
    exit 0
fi

# Authorize gerrit reindex from local-test netns
mysql -e "$(grep gerrit.*sftests.com \
    /var/lib/software-factory/sql/databases.sql | \
    sed 's/managesf.sftests.com/192.168.42.2/g')"

ip netns exec local-test sudo -E -u $SUDO_USER "$@"
