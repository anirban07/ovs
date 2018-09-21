#!/bin/bash

MASTER_IP='10.118.101.42'
mkdir -p /var/log/ovs-custom/
mkdir -p /var/run/openvswitch/

exec_db() {
 set -x
 /usr/share/openvswitch/scripts/ovn-ctl \
 --db-${1}-cluster-local-addr=$MASTER_IP \
 --db-${1}-file=/var/lib/openvswitch/ovn${1}_db.db \
 --ovn-${1}-logfile=/var/log/ovs-custom/ovsdb_${1}.log \
 start_${1}_ovsdb &
}

rm -f /var/lib/openvswitch/ovnnb_db.db
rm -f /var/log/ovs-custom/ovsdb_nb.log
exec_db nb

