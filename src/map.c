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

#define _GNU_SOURCE

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ply/ply.h>
#include <ply/bpf-syscall.h>
#include <ply/map.h>
#include <ply/symtable.h>
#include <ply/arch.h>

#define PTR_W ((int)(sizeof(uintptr_t) * 2))

void dump_sym(FILE *fp, node_t *integer, void *data)
{
	uintptr_t pc;
	const ksym_t *k;

	if (arch_reg_width() == 4)
		pc = *((uint32_t *)data);
	else
		pc = *((uint64_t *)data);

	k = G.ksyms ? ksym_get(G.ksyms, pc) : NULL;
	if (k) {
		fprintf(fp, "%-20s", k->sym);
		return;
	}

	fprintf(fp, "<%*.*" PRIxPTR ">", PTR_W, PTR_W, pc);
}

static void dump_int(FILE *fp, node_t *integer, void *data)
{
	int64_t num;

	/* copy, don't cast. we could be on a platform that does not
	 * handle unaligned accesses */
	memcpy(&num, data, sizeof(num));
	fprintf(fp, "%8" PRId64, num);
}

static void dump_str(FILE *fp, node_t *str, void *data)
{
	int size = (int)str->dyn->size;

	fprintf(fp, "%-*.*s", size, size, (const char *)data);
}

static void dump_stack(FILE *fp, node_t *stack, void *data)
{
	int64_t *_stack_id = data;
	uint32_t stack_id = *_stack_id;
	uint64_t ips[0x10];
	sym_t *s;
	int i;

	s = symtable_get_stack(node_get_script(stack)->dyn->script.st);
	if (!s) {
		_e("no stack map in symbol table");
		return;
	}

	if (bpf_map_lookup(s->map->fd, &stack_id, ips)) {
		_eno("failed to lookup stack-id:%#" PRIx32, stack_id);
		fprintf(fp, "<ERR stack-id:%#" PRIx32 ">", stack_id);
		return;
	}

	for (i = 0; i < 0x10; i++) {
		const ksym_t *k;

		if (!ips[i])
			break;

		k = G.ksyms ? ksym_get(G.ksyms, ips[i]) : NULL;
		if (k) {
			fprintf(fp, "\n\t%s", k->sym);

			ips[i] -= k->start;
			if (!ips[i])
				continue;

			fprintf(fp, "+%#"PRIxPTR, (uintptr_t)ips[i]);
			continue;
		}

		fprintf(fp, "\n\t<%*.*" PRIxPTR ">", PTR_W, PTR_W, (uintptr_t)ips[i]);
	}
}

void dump_rec(FILE *fp, node_t *rec, void *data, int len)
{
	node_t *first, *varg;
	int brackets = 0;

	first = rec->rec.vargs;
	if (!first || !len)
		return;

	if (first->next && (len > 1)) {
		fputs("[ ", fp);
		brackets = 1;
	}

	node_foreach(varg, first) {
		if (varg != first)
			fputs(", ", fp);

		dump_node(fp, varg, data);
		data += varg->dyn->size;

		if (!(--len))
			break;
	}

	if (brackets)
		fputs(" ]", fp);
}

void dump_node(FILE *fp, node_t *n, void *data)
{
	if (n->dump) {
		n->dump(fp, n, data);
		return;
	}

	switch (n->dyn->type) {
	case TYPE_INT:
		dump_int(fp, n, data);
		break;
	case TYPE_STR:
		dump_str(fp, n, data);
		break;
	case TYPE_STACK:
		dump_stack(fp, n, data);
		break;
	case TYPE_REC:
		dump_rec(fp, n, data, n->rec.n_vargs);
		break;
	default:
		_e("unknown node type  %d", n->dyn->type);
		break;
	}
}

int cmp_node(node_t *n, const void *a, const void *b)
{
	node_t *varg;
	int cmp;

	if (n->cmp)
		return n->cmp(n, a, b);

	switch (n->dyn->type) {
	case TYPE_INT:
	case TYPE_STACK:
		return *((int64_t *)a) - *((int64_t *)b);
	case TYPE_STR:
		return strncmp(a, b, n->dyn->size);
	case TYPE_REC:
		node_foreach(varg, n->rec.vargs) {
			cmp = cmp_node(varg, a, b);
			if (cmp)
				return cmp;

			a += varg->dyn->size;
			b += varg->dyn->size;
		}
		return 0;

	default:
		return 0;
	}

	return 0;
}

int cmp_map(const void *ak, const void *bk, void *_map)
{
	node_t *map = _map;
	node_t *rec = map->map.rec;
	const void *av = ak + rec->dyn->size;
	const void *bv = bk + rec->dyn->size;
	int cmp;

	if (map->dyn->map.cmp)
		return map->dyn->map.cmp(map, ak, bk);
	
	cmp = cmp_node(rec, ak, bk);
	if (cmp)
		return cmp;

	return cmp_node(map, av, bv);
}

static void __key_workaround(int fd, void *key, size_t key_sz, void *val)
{
	FILE *fp;
	int err;

	/* Yep, that's urandom baby! There seems to be no way to
	 * iterate over all keys in a map. However, if you ask for a
	 * non-existing key; the kernel will return the "first one". */
	fp = fopen("/dev/urandom", "r");

	while (1) {
		err = bpf_map_lookup(fd, key, val);
		if (err)
			break;

		if (fread(key, key_sz, 1, fp) != 1)
			break;
	}

	fclose(fp);
}

void dump_map(node_t *map)
{
	node_t *rec = map->map.rec;
	sym_t *s = sym_from_node(map);
	char *data, *key, *val;
	size_t rsize;
	int err, n = 0;

	rsize = s->map->ksize + s->map->vsize;

	data = malloc(rsize * s->map->nelem);
	assert(data);

	key = data;
	val = data + s->map->ksize;

	__key_workaround(s->map->fd, key, rec->dyn->size, val);

	for (err = bpf_map_next(s->map->fd, key, key); !err;
	     err = bpf_map_next(s->map->fd, key - rsize, key)) {
		err = bpf_map_lookup(s->map->fd, key, val);
		if (err)
			goto out_free;

		n++;
		key += rsize;
		val += rsize;
	}

	qsort_r(data, n, rsize, cmp_map, map);

	printf("\n%s:\n", map->string);

	if (map->dyn->map.dump) {
		map->dyn->map.dump(stdout, map, data, n);
		goto out_free;
	}

	for (key = data, val = data + rec->dyn->size; n > 0; n--) {
		dump_node(stdout, rec, key);
		fputs("\t", stdout);
		dump_node(stdout, map, val);
		fputs("\n", stdout);

		key += rsize;
		val += rsize;
	}
out_free:
	free(data);
}

int map_setup(node_t *script)
{
	int dumpfd = 0xfd00;
	sym_t *s;

	sym_foreach(s, script->dyn->script.st->syms) {
		if (s->type != TYPE_MAP || s->map->fd >= 0)
			continue;

		if (G.dump) {
			s->map->fd = dumpfd++;
			continue;
		}

		_d("%s: type:%d ksize:%#zx vsize:%#zx nelem:%#zx", s->name,
		   s->map->type, s->map->ksize, s->map->vsize, s->map->nelem);

		s->map->fd = bpf_map_create(s->map->type, s->map->ksize,
					    s->map->vsize, s->map->nelem);
		if (s->map->fd <= 0) {
			_eno("%s", s->name);
			return s->map->fd;
		}
	}

	return 0;
}

int map_teardown(node_t *script)
{
	sym_t *s;

	if (G.dump)
		return 0;

	sym_foreach(s, script->dyn->script.st->syms) {
		if (s->type != TYPE_MAP || s->map->fd == -1)
			continue;

		if (s->name[0] == '@')
			dump_map(s->map->map);

		close(s->map->fd);
		s->map->fd = -1;
	}

	return 0;
}
