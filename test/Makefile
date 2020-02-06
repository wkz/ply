sysroot-ver := 5.5.1
sysroot     := sysroot-$(sysroot-ver)
sysroot-tar := $(sysroot).tar.xz
sysroot-url := https://github.com/wkz/sysroot/releases/download/v$(sysroot-ver)

tc = $(1)-unknown-linux-gnu$(if $(filter $(1),arm),eabi,)
qarch = $(if $(filter $1,powerpc),ppc64,$1)
qemu = unshare -r qemu-system-$(call qarch,$(1)) $(2) -nographic -no-reboot \
	-kernel $(1)-$(sysroot)/boot/vmlinuz-$(sysroot-ver) \
	-device virtio-9p-pci,fsdev=root,mount_tag=/dev/root \
	-fsdev local,id=root,path=$(CURDIR)/$(1)-$(sysroot),security_model=none \
	-append "rw root=/dev/root rootfstype=9p rootflags=trans=virtio panic=-1 quiet init=/init script=test.sh $(3)"

check: aarch64-check arm-check powerpc-check x86_64-check

aarch64-check: aarch64-$(sysroot)/sbin/ply aarch64-$(sysroot)/bin/test.sh
	rm -f aarch64-$(sysroot)/result && \
	$(call qemu,aarch64,-M virt -cpu cortex-a53,console=ttyAMA0) && \
	exit $$(cat aarch64-$(sysroot)/result || echo 1)

arm-check: arm-$(sysroot)/sbin/ply arm-$(sysroot)/bin/test.sh
	rm -f arm-$(sysroot)/result && \
	$(call qemu,arm,-M virt -cpu cortex-a15,console=ttyAMA0) && \
	exit $$(cat arm-$(sysroot)/result || echo 1)

powerpc-check: powerpc-$(sysroot)/sbin/ply powerpc-$(sysroot)/bin/test.sh
	rm -f powerpc-$(sysroot)/result && \
	$(call qemu,powerpc,-M ppce500 -cpu e5500,console=ttyS0) && \
	exit $$(cat powerpc-$(sysroot)/result || echo 1)

x86_64-check: x86_64-$(sysroot)/sbin/ply x86_64-$(sysroot)/bin/test.sh
	rm -f x86_64-$(sysroot)/result && \
	$(call qemu,x86_64,,console=ttyS0) && \
	exit $$(cat x86_64-$(sysroot)/result || echo 1)

%-$(sysroot)/bin/test.sh: test.sh %-$(sysroot)/usr/include/linux/version.h
	cp $< $@

%-$(sysroot)/sbin/ply: %-ply-obj/src/ply/ply
	$(MAKE) -C $*-ply-obj DESTDIR=$(CURDIR)/$*-$(sysroot) install

%-ply-obj/src/ply/ply: %-ply-obj/Makefile
	$(MAKE) -C $*-ply-obj

%-ply-obj/Makefile: ../configure %-$(sysroot)/usr/include/linux/version.h |%-ply-obj
	cd $| && ../../configure \
		CPPFLAGS="-isystem $(CURDIR)/$*-$(sysroot)/usr/include" \
		--host=$(call tc,$*) --prefix=

%-ply-obj:
	mkdir $@

../configure:
	cd .. && ./autogen.sh

%-$(sysroot)/usr/include/linux/version.h: %-$(sysroot-tar)
	tar maxf $<
%-$(sysroot-tar):
	wget -q $(sysroot-url)/$*-$(sysroot-tar)

.SECONDARY:
.SILENT:
