#!/bin/bash

set -e

IMAGE_TEMPLATE=${IMAGE_TEMPLATE:-template-dib-centos-7}
SLAVE_TEMPLATE=${SLAVE_TEMPLATE:-dib-centos-7}

echo "Listing nodepool images ..."
IMAGES=$(openstack image list | awk "/$IMAGE_TEMPLATE/ { print \$2 }")

for image in $IMAGES; do
    echo "Removing slaves based on image $image"
    SLAVES=$(openstack server list --image $image | awk "/$SLAVE_TEMPLATE/ { print \$2 }")
    for slave in $SLAVES; do
        echo "Removing slave $slave ..."
        FLOATING_IPS=$(nova floating-ip-list | awk "/$slave/ { print \$4 }")
        for floating_ip in $FLOATING_IPS; do
            echo "Releasing floating IP $floating_ip ..."
            nova floating-ip-disassociate $slave $floating_ip
        done
        echo "Deleting slave $slave ..."
        openstack server delete --wait $slave
    done
    echo "Deleting image $image ..."
    openstack image delete $image
done
