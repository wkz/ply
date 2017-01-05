/*
 * Copyright 2015-2016 Tobias Waldekranz <tobias@waldekranz.com>
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

#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <sys/queue.h>

#include "../lang/ast.h"
#include "../compile.h"

typedef struct pvdr {
	TAILQ_ENTRY(pvdr) node;

	const char *name;
	
	int (*annotate)  (node_t *call);
	int (*loc_assign)(node_t *call);
	int  (*compile)  (node_t *call,  prog_t *prog);
	int    (*setup)  (node_t *probe, prog_t *prog);
	int (*teardown)  (node_t *probe);
} pvdr_t;

pvdr_t *pvdr_find    (const char *name);
int     pvdr_resolve (node_t *script);
void    pvdr_register(pvdr_t *pvdr);

int builtin_compile   (node_t *call, prog_t *prog);
int builtin_loc_assign(node_t *call);
int builtin_annotate  (node_t *call);

int default_loc_assign(node_t *call);

void printf_drain     (node_t *script);
int  printf_compile   (node_t *call, prog_t *prog);
int  printf_loc_assign(node_t *call);
int  printf_annotate  (node_t *call);

int  quantize_compile   (node_t *call, prog_t *prog);
int  quantize_loc_assign(node_t *call);
int  quantize_annotate  (node_t *call);

#endif	/* _PROVIDER_H */
