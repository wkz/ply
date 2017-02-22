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

typedef struct ksym {
	uintptr_t start;
	uintptr_t end;
	char sym[0x40 - (sizeof(uintptr_t) * 2)];
} ksym_t;

struct ksym_cache_hdr {
	uint32_t version;
	uint32_t n_syms;
};

struct ksym_cache {
	struct ksym_cache_hdr hdr;
	ksym_t sym[0];
};

typedef struct ksyms {
	int cache_fd;
	struct ksym_cache *cache;
} ksyms_t;

const ksym_t *ksym_get(ksyms_t *ks, uintptr_t addr);
ksyms_t *ksyms_new(void);

#endif	/* __KALLSYMS_H */
