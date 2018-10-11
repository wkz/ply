/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __KALLSYMS_H
#define __KALLSYMS_H

#include <inttypes.h>

struct ksym {
	uintptr_t addr;
	char sym[0x40 - sizeof(uintptr_t)];
};

struct ksym_cache_hdr {
	uint32_t n_syms;
	char _reserved[0x40 - sizeof(uint32_t)];
};

struct ksym_cache {
	struct ksym_cache_hdr hdr;

	struct ksym sym[0];
};

struct ksyms {
	int cache_fd;
	struct ksym_cache *cache;
};

int ksym_fprint(struct ksyms *ks, FILE *fp, uintptr_t addr);
const struct ksym *ksym_get(struct ksyms *ks, uintptr_t addr);

void ksyms_free(struct ksyms *ks);
struct ksyms *ksyms_new(void);

#define ksyms_foreach(_sym, _ks)					\
	for ((_sym) = &(_ks)->cache->sym[1];				\
	     (_sym) < &(_ks)->cache->sym[(_ks)->cache->hdr.n_syms - 2]; \
	     (_sym)++)

#endif	/* __KALLSYMS_H */
