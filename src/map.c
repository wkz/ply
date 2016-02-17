#define _GNU_SOURCE

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ply.h"
#include "bpf-syscall.h"
#include "map.h"

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

static void dump_node(FILE *fp, node_t *n, void *data)
{
	node_t *varg;

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
	case TYPE_REC:
		fputs("[ ", fp);

		node_foreach(varg, n->rec.vargs) {
			if (varg != n->rec.vargs)
				fputs(", ", fp);

			dump_node(fp, varg, data);
			data += varg->dyn.size;
		}

		fputs(" ]", fp);
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
	/* char *key = calloc(1, rec->dyn.size), *val = malloc(map->dyn.size); */
	char *key = data, *val = data + rec->dyn.size;
	int err, n = 0;

	__key_workaround(mdyn->mapfd, key, rec->dyn.size, val);

	for (err = bpf_map_next(mdyn->mapfd, key, key); !err;
	     err = bpf_map_next(mdyn->mapfd, key - entry_size, key)) {
		err = bpf_map_lookup(mdyn->mapfd, key, val);
		if (err)
			return;

		n++;
		key += entry_size;
		val += entry_size;
	}

	qsort_r(data, n, entry_size, cmp_mdyn, mdyn);

	printf("\n%s:\n", map->string);

	if (mdyn->dump)
		return mdyn->dump(stdout, map, data);

	for (key = data, val = data + rec->dyn.size; n > 0; n--) {
		dump_node(stdout, rec, key);
		fputs("\t", stdout);
		dump_node(stdout, map, val);
		fputs("\n", stdout);

		key += entry_size;
		val += entry_size;
	}
}

int map_setup(node_t *script)
{
	mdyn_t *mdyn;
	int dumpfd = 0xfd00;
	size_t ksize, vsize;

	for (mdyn = script->dyn.script.mdyns; mdyn; mdyn = mdyn->next) {
		if (dump) {
			mdyn->mapfd = dumpfd++;
			continue;
		}

		if (!strcmp(mdyn->map->string, "printf")) {
			ksize = mdyn->map->dyn.size;
			vsize = mdyn->map->call.vargs->next->dyn.size;
		} else {
			ksize = mdyn->map->map.rec->dyn.size;
			vsize = mdyn->map->dyn.size;
		}

		mdyn->mapfd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, vsize, MAP_LEN);
		if (mdyn->mapfd <= 0) {
			_pe("failed creating map");
			return mdyn->mapfd;
		}
	}

	return 0;
}

int map_teardown(node_t *script)
{
	mdyn_t *mdyn;

	if (dump)
		return 0;

	for (mdyn = script->dyn.script.mdyns; mdyn; mdyn = mdyn->next) {
		if (mdyn->mapfd) {
			if (strcmp(mdyn->map->string, "printf"))
				dump_mdyn(mdyn);

			close(mdyn->mapfd);
		}
	}

	return 0;
}
