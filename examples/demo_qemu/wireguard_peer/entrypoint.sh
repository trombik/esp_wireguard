#! /bin/bash

TCPDUMP_LOG_FILE="/var/log/wireguard/tcpdump.log"

mkdir -p /var/log/wireguard
touch $TCPDUMP_LOG_FILE

wg-quick up wg0

if [ $? -ne 0 ]; then
    echo "WireGuard failed to start"
    exit 1
fi

tcpdump -i wg0 2>&1 | while read line; do echo "$(date) $line"; done >> $TCPDUMP_LOG_FILE &


tail -f $TCPDUMP_LOG_FILE
