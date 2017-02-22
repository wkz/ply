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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <ply/ast.h>
#include <ply/map.h>
#include <ply/module.h>
#include <ply/ply.h>

static int method_count_compile(node_t *call, prog_t *prog)
{
	node_t *map = call->parent->method.map;

	emit(prog, LDXDW(BPF_REG_0, map->dyn->addr, BPF_REG_10));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_0, 1));
	emit(prog, STXDW(BPF_REG_10, map->dyn->addr, BPF_REG_0));
	return 0;
}

static int method_count_cmp(node_t *map, const void *ak, const void *bk)
{
	node_t *rec = map->map.rec;
	const void *av = ak + rec->dyn->size;
	const void *bv = bk + rec->dyn->size;
	int cmp;

	cmp = cmp_node(map, av, bv);
	if (cmp)
		return cmp;

	return cmp_node(rec, ak, bk);
	
}

static int method_count_loc_assign(node_t *call)
{
	node_t *map = call->parent->method.map;

	map->dyn->map.cmp = method_count_cmp;
	return default_loc_assign(call);
}

static int method_count_annotate(node_t *call)
{
	if (call->call.vargs ||
	    call->parent->type != TYPE_METHOD)
		return -EINVAL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);

	return 0;
}
MODULE_FUNC_LOC(method, count);

extern const func_t quantize_func;

static const func_t *method_funcs[] = {
	&method_count_func,
	&quantize_func,
	NULL
};

int method_get_func(const module_t *m, node_t *call, const func_t **f)
{
	return generic_get_func(method_funcs, call, f);
}

module_t method_module = {
	.name = "method",
	.get_func = method_get_func,
};
