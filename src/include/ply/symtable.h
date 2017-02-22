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

#ifndef _PLY_SYMTABLE_H
#define _PLY_SYMTABLE_H

#include <stdio.h>

#include <ply/ast.h>

typedef struct sym sym_t;

struct sym_map_data {
	int fd;
	enum bpf_map_type type;
	size_t ksize, vsize, nelem;

	node_t *map;
};

struct sym {
	sym_t *next, *prev;

	char   *name;
	node_t *probe;

	dyn_t dyn;

	type_t type;
	union {
		struct {
			node_t *first, *last;
		} var;

		struct sym_map_data *map;
	};
};

#define sym_foreach(_s, _in) for((_s) = (_in); (_s); (_s) = (_s)->next)

static inline sym_t *sym_from_node(node_t *n)
{
	if (n->type != TYPE_MAP &&
	    n->type != TYPE_VAR)
		return NULL;

	return container_of(n->dyn, sym_t, dyn);
}

int sym_map_sync(node_t *map);

int sym_fdump(sym_t *s, FILE *fp);


typedef struct symtable {
	sym_t *syms;
} symtable_t;

int symtable_fdump(symtable_t *st, FILE *fp);

sym_t *symtable_get_stack(symtable_t *st);
int    symtable_ref_stack(symtable_t *st);

int    symtable_populate(symtable_t *st, node_t *script);

#endif	/* _PLY_SYMTABLE_H */
