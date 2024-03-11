check-timeout := 300

arch-list := armv7 aarch64 x86_64

tc-arch-armv7   := armv7-eabihf
tc-arch-aarch64 := aarch64
tc-arch-x86_64  := x86-64

host-armv7   := arm
host-aarch64 := aarch64
host-x86_64  := x86_64

al = alpine-minirootfs-3.19.1-$(1)
lx = linux-virt-6.6.21-r0
tc = $(tc-arch-$(1))--musl--bleeding-edge-2024.02-1

al-repo := https://dl-cdn.alpinelinux.org/alpine/v3.19
tc-repo := https://toolchains.bootlin.com/downloads/releases/toolchains

al-tar = $(call al,$(1)).tar.gz
al-url = $(al-repo)/releases/$(1)/$(call al-tar,$(1))
lx-tar = $(lx).apk
lx-url = $(al-repo)/main/$(1)/$(lx-tar)
tc-tar = $(call tc,$(1)).tar.bz2
tc-url = $(tc-repo)/$(tc-arch-$(1))/tarballs/$(call tc-tar,$(1))

qemu-opts = -cpu max -m 256M \
	-nographic -no-reboot \
	-kernel work/$(1)-rootfs/boot/vmlinuz-virt \
	-initrd work/$(1)-rootfs.cpio.gz \
	-watchdog i6300esb \
	-append "$(2) panic=-1 root=initramfs ramdisk_size=64000 rdinit=/sbin/init quiet"

qemu-armv7 = qemu-system-arm -M virt,highmem=off \
	$(call qemu-opts,armv7)

qemu-aarch64 = qemu-system-aarch64 -M virt \
	-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
	$(call qemu-opts,aarch64)

qemu-x86_64 = qemu-system-x86_64 -M pc \
	-bios /usr/share/qemu/OVMF.fd \
	$(call qemu-opts,x86_64,console=ttyS0)


all: check
check: $(addsuffix -check,$(arch-list))
build: $(addsuffix -build,$(arch-list))

define arch

$(1)-shell: work/$(1)-rootfs.cpio.gz
	$(qemu-$(1))

$(1)-check: work/$(1)-rootfs.cpio.gz
	rm -f work/$(1)-check
	$(qemu-$(1)) \
		-device virtio-serial \
		-device virtserialport,name=check,chardev=check \
		-chardev file,id=check,path=work/$(1)-check
	test "`cat work/$(1)-check`" -eq 0


# Install ply & test scripts

work/$(1)-rootfs.cpio.gz: \
		work/$(1)-rootfs \
		work/$(1)-rootfs/boot/vmlinuz-virt \
		$(1)-install \
		work/$(1)-rootfs/lib/ply/test.sh
	cd work/$(1)-rootfs && find . \
		| cpio -o -H newc \
		| gzip >../$(1)-rootfs.cpio.gz

work/$(1)-rootfs/lib/ply/test.sh: rootfs rootfs/lib/ply/test.sh |work/$(1)-rootfs
	rsync -a $$</ $$|


# Ply

$(1)-install: $(1)-build |work/$(1)-rootfs
	PATH=$(CURDIR)/cache/$(call tc,$(1))/bin:$(PATH) \
		$(MAKE) -C work/$(1)-ply DESTDIR=$(CURDIR)/work/$(1)-rootfs install

$(1)-build: work/$(1)-ply/Makefile
	PATH=$(CURDIR)/cache/$(call tc,$(1))/bin:$(PATH) \
		$(MAKE) -C $$(<D)

work/$(1)-ply/Makefile: ../configure |work/$(1)-ply cache/$(call tc,$(1))
	cd $$(@D) && PATH=$(CURDIR)/cache/$(call tc,$(1))/bin:$(PATH) \
		../../../configure \
			CFLAGS="-Wall -Wextra -Werror" \
			--host=$(host-$(1))-linux --prefix=

work/$(1)-ply:
	mkdir -p $$@


# Root filesystem

work/$(1)-rootfs: cache/$(call al-tar,$(1))
	mkdir -p $$@
	tar -C $$@ -maxf $$<

cache/$(call al-tar,$(1)): |cache
	wget -O $$@ $(call al-url,$(1))


# Kernel

work/$(1)-rootfs/boot/vmlinuz-virt: cache/linux-$(1).tar.gz |work/$(1)-rootfs
	tar -C work/$(1)-rootfs -maxf $$< 2>/dev/null

cache/linux-$(1).tar.gz: |cache
	wget -O $$@ $(call lx-url,$(1))


# Toolchain

cache/$(call tc,$(1)): cache/$(call tc-tar,$(1))
	tar -C $$(@D) -maxf $$<

cache/$(call tc-tar,$(1)): |cache
	wget -O $$@ $(call tc-url,$(1))

endef

$(eval $(call arch,armv7))
$(eval $(call arch,aarch64))
$(eval $(call arch,x86_64))

cache:
	mkdir -p $@

../configure:
	cd .. && ./autogen.sh


.PHONY: all check build \
	$(addsuffix -build,$(arch-list)) $(addsuffix -install,$(arch-list)) \
	$(addsuffix -check,$(arch-list)) $(addsuffix -shell,$(arch-list))
