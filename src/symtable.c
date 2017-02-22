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

#include <ply/bpf-syscall.h>
#include <ply/ply.h>
#include <ply/symtable.h>

#include "config.h"

int sym_fdump(sym_t *s, FILE *fp)
{
	int w;

	if (s->type != TYPE_MAP && s->type != TYPE_VAR) {
		_d("corrupt sym (%s)", type_str(s->type));
		return -EINVAL;
	} else if (s->type == TYPE_MAP && !strcmp(s->name, "stack")) {
		fprintf(fp, "%s\n", s->name);
		return 0;
	}

	fprintf(fp, "%s(%s)%n", s->name, s->probe->string, &w);
	if (w < 40)
		fprintf(fp, "%*s", 40 - w, "");

	fprintf(fp, " (type:%s/%s size:0x%zx loc:%s",
		type_str(s->type), type_str(s->dyn.type),
		s->dyn.size, loc_str(s->dyn.loc));

	switch (s->dyn.loc) {
	case LOC_NOWHERE:
	case LOC_VIRTUAL:
		break;
	case LOC_REG:
		fprintf(fp, "/%d", s->dyn.reg);
		break;
	case LOC_STACK:
		fprintf(fp, "/-0x%zx", -s->dyn.addr);
		break;
	}

	fputs(")", fp);
	return 0;
}

static int __sync_size(size_t *known, size_t new)
{
	if (!new)
		return 0;

	if (!(*known)) {
		*known = new;
		return 0;
	}

	if (*known != new)
		return -EINVAL;

	return 0;
}

int sym_map_sync(node_t *map)
{
	node_t *rec = map->map.rec;
	sym_t *s;
	int err;

	s = sym_from_node(map);
	if (!s) {
		_e("unknown map '%s'", map->string);
		return -EINVAL;
	}

	err = __sync_size(&s->map->vsize, map->dyn->size);
	if (err) {
		_e("conflicting key sizes for '%s' %zd != %zd",
		   s->name, map->dyn->size, s->map->vsize);
		return err;
	}

	err = __sync_size(&s->map->ksize, rec->dyn->size);
	if (err) {
		_e("conflicting value sizes for '%s' %zd != %zd",
		   s->name, rec->dyn->size, s->map->ksize);
		return err;
	}

	return 0;
}

int symtable_fdump(symtable_t *st, FILE *fp)
{
	sym_t *s;
	int err = 0;

	fputs("symtable:\n", fp);
	sym_foreach(s, st->syms) {
		err = sym_fdump(s, fp);
		fputc('\n', fp);
		if (err)
			return err;
	}

	return 0;
}

#ifdef LINUX_HAS_STACKMAP
sym_t *symtable_get_stack(symtable_t *st)
{
	sym_t *s;

	sym_foreach(s, st->syms) {
		if (s->type == TYPE_MAP && !strcmp(s->name, "stack"))
			return s;
	}

	return NULL;
}

int symtable_ref_stack(symtable_t *st)
{
	sym_t *s;

	s = symtable_get_stack(st);
	if (s)
		return 0;

	s = calloc(1, sizeof(*s));
	assert(s);

	s->type = TYPE_MAP;
	s->name = strdup("stack"); /* user maps start with @ => no conflict */

	s->map = calloc(1, sizeof(*s->map));
	assert(s->map);

	s->map->type  = BPF_MAP_TYPE_STACK_TRACE;
	s->map->ksize = sizeof(uint32_t);
	s->map->vsize = sizeof(uint64_t) * 0x10; /* save 16 frames */
	s->map->nelem = G.map_nelem;
	s->map->fd    = -1;

	if (st->syms)
		insque_tail(s, st->syms);
	else
		st->syms = s;

	return 0;
}
#else
sym_t *symtable_get_stack(symtable_t *st) { return NULL; }
int    symtable_ref_stack(symtable_t *st) { _d(""); return -ENOSYS; }
#endif	/* LINUX_HAS_STACKMAP */

static sym_t *symtable_get(symtable_t *st, node_t *n)
{
	sym_t *s;

	sym_foreach(s, st->syms) {
		if (s->type == n->type &&
		    !strcmp(s->name, n->string) &&
		    node_get_probe(n) == s->probe)
			return s;
	}

	return NULL;
}

static sym_t *symtable_new(symtable_t *st, node_t *n)
{
	sym_t *s;

	s = calloc(1, sizeof(*s));
	assert(s);

	s->type  = n->type;
	s->name  = strdup(n->string);
	s->probe = node_get_probe(n);

	if (st->syms)
		insque_tail(s, st->syms);
	else
		st->syms = s;

	return s;
}

static struct sym_map_data *symtable_map_data(symtable_t *st, sym_t *ms)
{
	struct sym_map_data *md;
	sym_t *s;

	sym_foreach(s, st->syms) {
		if (s->type == ms->type &&
		    !strcmp(s->name, ms->name) &&
		    s->map)
			return s->map;
	}

	md = calloc(1, sizeof(*md));
	assert(md);

	md->fd    = -1;
	md->type  = BPF_MAP_TYPE_HASH;
	md->nelem = G.map_nelem;
	return md;
}

static int symtable_map_ref(symtable_t *st, node_t *map)
{
	sym_t *s;

	s = symtable_get(st, map);
	if (s)
		goto found;

	s = symtable_new(st, map);
	s->map = symtable_map_data(st, s);
	s->map->map = map;

found:
	map->dyn = &s->dyn;
	return 0;
}

static int symtable_var_ref(symtable_t *st, node_t *var)
{
	node_t *unroll;
	sym_t *s;

	s = symtable_get(st, var);
	if (s) {
		s->var.last = var;
		goto found;
	}

	s = symtable_new(st, var);
	s->var.first = s->var.last = var;

	unroll = node_get_parent_of_type(TYPE_UNROLL, var);
	if (unroll)
		s->var.last = unroll;
		
found:
	var->dyn = &s->dyn;
	return 0;

}

static int _symtable_populate(node_t *n, void *_st)
{
	symtable_t *st = _st;

	switch (n->type) {
	case TYPE_MAP:
		return symtable_map_ref(st, n);
	case TYPE_VAR:
		return symtable_var_ref(st, n);

	default:
		break;
	}

	return 0;
}

int symtable_populate(symtable_t *st, node_t *script)
{
	return node_walk(script, NULL, _symtable_populate, st);
}
