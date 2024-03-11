#!/bin/sh

for vport in /dev/vport*; do
    name=$(cat /sys/class/virtio-ports/$(basename $vport)/name)
    if [ "$name" = "check" ]; then
	echo "Running test suite" >/dev/console
	/lib/ply/test.sh >/dev/console 2>&1

	echo $? >$vport
	sync

	poweroff -ff
	exit
    fi
done;

echo "Launching interactive shell" >/dev/console
