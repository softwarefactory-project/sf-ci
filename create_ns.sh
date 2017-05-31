#!/bin/sh
# Simple netns creation

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

ip netns exec local-test sudo -u $SUDO_USER "$@"
