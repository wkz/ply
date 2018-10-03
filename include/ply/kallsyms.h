/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
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
