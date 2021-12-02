check-timeout := 300

arch-basis   := arm
arch-coronet := powerpc
arch-dagger  := arm
arch-envoy   := aarch64
arch-zero    := x86_64
arch-list    := armv5 powerpc armv7 aarch64 x86_64
plat-list    := basis coronet dagger envoy zero

tc-mach-basis   := armv5-eabi
tc-mach-coronet := powerpc-e500mc
tc-mach-dagger  := armv7-eabihf
tc-mach-envoy   := aarch64
tc-mach-zero    := x86-64-core-i7

tc = $(tc-mach-$(1))--glibc--bleeding-edge-2020.08-1
tc-tar = $(call tc,$(1)).tar.bz2
tc-url = https://toolchains.bootlin.com/downloads/releases/toolchains/$(tc-mach-$(1))/tarballs/$(call tc-tar,$(1))

# CI build of netbox@5401a42ea064
nb-run = 3861903284
nb-url = https://nightly.link/westermo/netbox/suites/$(nb-run)/artifacts/$(1)
nb-url-basis   := $(call nb-url,95999414)
nb-url-coronet := $(call nb-url,95999415)
nb-url-dagger  := $(call nb-url,95999416)
nb-url-envoy   := $(call nb-url,95999417)
nb-url-zero    := $(call nb-url,95999418)

qemu-opts = \
	-display none -no-reboot \
	-kernel work/$(1)-rootfs/boot/*Image \
	-initrd work/$(1)-rootfs.img \
	-watchdog i6300esb \
	-device virtio-serial -chardev stdio,mux=on,id=hvc0 \
	-device virtconsole,name=console,chardev=hvc0 -mon chardev=hvc0 \
	-append "panic=-1 root=/dev/ram ramdisk_size=64000 console=hvc0 quiet"

qemu-basis = qemu-system-arm -M versatilepb \
	-dtb cache/netbox-os-basis/versatile-pb.dtb \
	$(call qemu-opts,basis)

qemu-coronet = qemu-system-ppc64 -M ppce500 -cpu e5500 \
	$(call qemu-opts,coronet)

qemu-dagger = qemu-system-arm -M virt,highmem=off -cpu max \
	$(call qemu-opts,dagger)

qemu-envoy = qemu-system-aarch64 -M virt -cpu max \
	$(call qemu-opts,envoy)

qemu-zero = qemu-system-x86_64 -M pc -cpu max \
	$(call qemu-opts,zero)


all: check
check: $(addsuffix -check,$(plat-list))
build: $(addsuffix -build,$(plat-list))

armv5-check: basis-check
armv5-build: basis-build

powerpc-check: coronet-check
powerpc-build: coronet-build

armv7-check: dagger-check
armv7-build: dagger-build

aarch64-check: envoy-check
aarch64-build: envoy-build

x86_64-check: zero-check
x86_64-build: zero-build

define platform

$(1)-shell: work/$(1)-rootfs.img
	$(qemu-$(1))

$(1)-check: work/$(1)-rootfs.img
	rm -f work/$(1)-check
	$(qemu-$(1)) \
		-device virtserialport,name=check,chardev=check \
		-chardev file,id=check,path=work/$(1)-check
	test "`cat work/$(1)-check`" -eq 0


# Install ply & test scripts

work/$(1)-rootfs.img: $(1)-install \
		work/$(1)-rootfs/lib/ply/test.sh \
		work/$(1)-rootfs/lib/ply/test-wrapper.sh \
		work/$(1)-rootfs/etc/finit.d/test.conf
	mksquashfs work/$(1)-rootfs $$@ -all-root -noappend

work/$(1)-rootfs/lib/ply/test.sh: test.sh |work/$(1)-rootfs
	mkdir -p $$(@D) && cp $$< $$@
work/$(1)-rootfs/lib/ply/test-wrapper.sh: test-wrapper.sh |work/$(1)-rootfs
	mkdir -p $$(@D) && cp $$< $$@
work/$(1)-rootfs/etc/finit.d/test.conf: test.conf |work/$(1)-rootfs
	mkdir -p $$(@D) && cp $$< $$@


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
			--host=$(arch-$(1))-linux --prefix=

work/$(1)-ply:
	mkdir -p $$@


# NetBox

work/$(1)-rootfs: cache/netbox-os-$(1)/netbox-os-$(1).img
	unsquashfs -f -q -d $$@ $$< && touch $$@

cache/netbox-os-$(1)/netbox-os-$(1).img: cache/netbox-os-$(1).tar.gz
	tar -C cache/ -maxf $$<

cache/netbox-os-$(1).tar.gz: cache/netbox-os-$(1)-$(nb-run).zip
	unzip -DD -o -d $$(@D) $$<

cache/netbox-os-$(1)-$(nb-run).zip: |cache
	wget -O $$@ $(nb-url-$(1))


# Bootlin toolchain

cache/$(call tc,$(1)): cache/$(call tc-tar,$(1))
	tar -C $$(@D) -maxf $$<

cache/$(call tc-tar,$(1)): |cache
	wget -O $$@ $(call tc-url,$(1))

endef

$(eval $(call platform,basis))
$(eval $(call platform,coronet))
$(eval $(call platform,dagger))
$(eval $(call platform,envoy))
$(eval $(call platform,zero))

cache:
	mkdir -p $@

../configure:
	cd .. && ./autogen.sh


.PHONY: all check build \
	$(addsuffix -build,$(plat-list)) $(addsuffix -install,$(plat-list)) \
	$(addsuffix -check,$(plat-list)) $(addsuffix -shell,$(plat-list)) \
	\
	$(addsuffix -build,$(arch-list)) $(addsuffix -check,$(arch-list))
