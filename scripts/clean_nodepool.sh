#!/bin/bash

set -e

IMAGE_TEMPLATE=${IMAGE_TEMPLATE:-template-dib-centos-7}
SLAVE_TEMPLATE=${SLAVE_TEMPLATE:-dib-centos-7}

SLAVES=$(openstack server list --name $SLAVE_TEMPLATE -f value -c ID)
for slave in $SLAVES; do
    echo "Removing slave $slave ..."
    FLOATING_IPS=$(openstack server show $slave -f value -c addresses | \
                            awk '{print $2}')
    for floating_ip in $FLOATING_IPS; do
        echo "Releasing floating IP $floating_ip ..."
        openstack server remove floating ip $slave $floating_ip
        echo "Delete floating IP $floating_ip ..."
        openstack floating ip delete $floating_ip
    done
    echo "Deleting slave $slave ..."
    openstack server delete --wait $slave
done

echo "Listing nodepool images ..."
IMAGES=$(openstack image list | awk "/$IMAGE_TEMPLATE/ { print \$2 }")
for image in $IMAGES; do
    echo "Deleting image $image ..."
    openstack image delete $image
done
