#!/bin/sh

for vport in /dev/vport*; do
    name=$(cat /sys/class/virtio-ports/$(basename $vport)/name)
    if [ "$name" = "check" ]; then
	echo ": running" >/dev/console
	/lib/ply/test.sh >/dev/console 2>&1

	echo $? >$vport
	sync

	reboot
	exit
    fi
done;

echo ": skipping" >/dev/console
