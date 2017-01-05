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

#define _GNU_SOURCE

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ply.h"
#include "bpf-syscall.h"
#include "map.h"

static void dump_node(FILE *fp, node_t *n, void *data);

void dump_sym(FILE *fp, node_t *integer, void *data)
{
	uint64_t *target = data;
	FILE *ksyms;
	char *pos, *line[2];
	uint64_t addr[2] = { ULLONG_MAX, ULLONG_MAX };
	int i = 0;

	line[0] = malloc(256);
	line[1] = malloc(256);
	assert(line[0] && line[1]);

	ksyms = fopen("/proc/kallsyms", "r");
	if (!ksyms) {
		_e("unable to read out kernel symbols");
		goto fallback;
	}

	for (i = 0; fgets(line[i], 256, ksyms); i = !i) {
		addr[i] = strtoull(line[i], NULL, 16);
		if (addr[i] == ULLONG_MAX)
			goto fallback;

		if (addr[i] == *target)
			break;

		if (addr[i] > *target) {
			i = !i;
			break;
		}
	}

	pos = strchr(line[i], '\n');
	if (pos)
		*pos = '\0';

	pos = strrchr(line[i], ' ');
	if (!pos)
		goto fallback;

	fprintf(fp, "%-20s", pos + 1);
	fclose(ksyms);
	return;

fallback:
	if (ksyms)
		fclose(ksyms);

	fprintf(fp, "<%8" PRIx64 ">", *((int64_t *)data));
}

static void dump_int(FILE *fp, node_t *integer, void *data)
{
	fprintf(fp, "%8" PRId64, *((int64_t *)data));
}

static void dump_str(FILE *fp, node_t *str, void *data)
{
	int size = (int)str->dyn.size;

	fprintf(fp, "%-*.*s", size, size, (const char *)data);
}

static void dump_stack(FILE *fp, node_t *stack, void *data)
{
	int i, fd = node_map_get_fd(stack);
	int64_t *_stack_id = data;
	uint32_t stack_id = *_stack_id;
	uint64_t ips[0x10];

	if (bpf_map_lookup(fd, &stack_id, ips)) {
		_eno("failed to lookup stack-id:%#" PRIx32, stack_id);
		fprintf(fp, "<ERR stack-id:%#" PRIx32 ">", stack_id);
		return;
	}

	for (i = 0; i < 0x10; i++) {
		if (!ips[i])
			break;

		fprintf(fp, "\n\t<%*.*" PRIx64 ">",
			sizeof(uintptr_t) * 2, sizeof(uintptr_t) * 2, ips[i]);
	}
}

void dump_rec(FILE *fp, node_t *rec, void *data, int len)
{
	node_t *first, *varg;
	int brackets = 0;

	if (rec->parent->type == TYPE_MAP && rec->parent->map.is_var) {
		len--;
		first = rec->rec.vargs->next;
		data += rec->rec.vargs->dyn.size;
	} else {
		first = rec->rec.vargs;
	}

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
		data += varg->dyn.size;

		if (!(--len))
			break;
	}

	if (brackets)
		fputs(" ]", fp);
}

static void dump_node(FILE *fp, node_t *n, void *data)
{
	if (n->dump) {
		n->dump(fp, n, data);
		return;
	}

	switch (n->dyn.type) {
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
		_e("unknown node type  %d", n->dyn.type);
		break;
	}
}

int cmp_node(node_t *n, const void *a, const void *b)
{
	node_t *varg;
	int cmp;

	if (n->cmp)
		return n->cmp(n, a, b);

	switch (n->dyn.type) {
	case TYPE_INT:
	case TYPE_STACK:
		return *((int64_t *)a) - *((int64_t *)b);
	case TYPE_STR:
		return strncmp(a, b, n->dyn.size);
	case TYPE_REC:
		node_foreach(varg, n->rec.vargs) {
			cmp = cmp_node(varg, a, b);
			if (cmp)
				return cmp;

			a += varg->dyn.size;
			b += varg->dyn.size;
		}
		return 0;

	default:
		return 0;
	}

	return 0;
}

int cmp_mdyn(const void *ak, const void *bk, void *_mdyn)
{
	mdyn_t *mdyn = _mdyn;
	node_t *map = mdyn->map, *rec = map->map.rec;
	const void *av = ak + rec->dyn.size;
	const void *bv = bk + rec->dyn.size;
	int cmp;

	if (mdyn->cmp)
		return mdyn->cmp(map, ak, bk);
	
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

		fread(key, key_sz, 1, fp);
	}

	fclose(fp);
}

void dump_mdyn(mdyn_t *mdyn)
{
	node_t *map = mdyn->map, *rec = map->map.rec;
	size_t entry_size = rec->dyn.size + map->dyn.size;
	char *data = malloc(entry_size*MAP_LEN);
	char *key = data, *val = data + rec->dyn.size;
	int err, n = 0;

	__key_workaround(mdyn->mapfd, key, rec->dyn.size, val);

	for (err = bpf_map_next(mdyn->mapfd, key, key); !err;
	     err = bpf_map_next(mdyn->mapfd, key - entry_size, key)) {
		err = bpf_map_lookup(mdyn->mapfd, key, val);
		if (err)
			goto out_free;

		n++;
		key += entry_size;
		val += entry_size;
	}

	qsort_r(data, n, entry_size, cmp_mdyn, mdyn);

	printf("\n%s:\n", map->string);

	if (mdyn->dump) {
		mdyn->dump(stdout, map, data, n);
		goto out_free;
	}

	for (key = data, val = data + rec->dyn.size; n > 0; n--) {
		dump_node(stdout, rec, key);
		fputs("\t", stdout);
		dump_node(stdout, map, val);
		fputs("\n", stdout);

		key += entry_size;
		val += entry_size;
	}
out_free:
	free(data);
}

int map_setup(node_t *script)
{
	mdyn_t *mdyn;
	int dumpfd = 0xfd00;

	for (mdyn = script->dyn.script.mdyns; mdyn; mdyn = mdyn->next) {
		size_t max_len = mdyn->map->map.max_len;
		size_t ksize, vsize;

		if (G.dump) {
			mdyn->mapfd = dumpfd++;
			continue;
		}

		if (!strcmp(mdyn->map->string, "printf")) {
			ksize   = mdyn->map->dyn.size;
			vsize   = mdyn->map->call.vargs->next->dyn.size;
			max_len = PRINTF_BUF_LEN;
		} else if (!strcmp(mdyn->map->string, "stack")) {
			ksize   = 4;
			vsize   = 0x80;
			max_len = MAP_LEN;
		} else {
			ksize = mdyn->map->map.rec->dyn.size;
			vsize = mdyn->map->dyn.size;
		}

		mdyn->mapfd = bpf_map_create(mdyn->type, ksize, vsize, max_len);
		if (mdyn->mapfd <= 0) {
			_eno("%s", mdyn->map->string);
			return mdyn->mapfd;
		}
	}

	return 0;
}

int map_teardown(node_t *script)
{
	mdyn_t *mdyn;

	if (G.dump)
		return 0;

	for (mdyn = script->dyn.script.mdyns; mdyn; mdyn = mdyn->next) {
		if (mdyn->mapfd) {
			if (mdyn->map->string[0] == '$')
				dump_mdyn(mdyn);

			close(mdyn->mapfd);
		}
	}

	return 0;
}
