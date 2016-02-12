#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "ply.h"
#include "bpf-syscall.h"
#include "map.h"

static void int_dump(node_t *integer, void *data)
{
	printf("%8" PRId64, *((int64_t *)data));
}

static void str_dump(node_t *str, void *data)
{
	printf("%-*.*s", (int)str->dyn.size, (int)str->dyn.size,
	       (const char *)data);
}

static void node_dump(node_t *n, void *data)
{
	node_t *varg;

	switch (n->dyn.type) {
	case TYPE_INT:
		int_dump(n, data);
		break;
	case TYPE_STR:
		str_dump(n, data);
		break;
	case TYPE_REC:
		fputs("[ ", stdout);

		node_foreach(varg, n->rec.vargs) {
			if (varg != n->rec.vargs)
				fputs(", ", stdout);

			node_dump(varg, data);
			data += varg->dyn.size;
		}

		fputs(" ]", stdout);
		break;
	default:
		_e("unknown node type  %d", n->dyn.type);
		break;
	}
}

static void __key_workaround(int fd, void *key, size_t key_sz, void *val)
{
	FILE *fp;
	int err;

	fp = fopen("/dev/urandom", "r");

	while (1) {
		err = bpf_map_lookup(fd, key, val);
		if (err)
			break;

		fread(key, key_sz, 1, fp);
	}

	fclose(fp);
}	

void map_dump(mdyn_t *mdyn)
{
	node_t *map = mdyn->map, *rec = map->map.rec;
	char *key = calloc(1, rec->dyn.size), *val = malloc(map->dyn.size);
	int err;

	__key_workaround(mdyn->mapfd, key, rec->dyn.size, val);

	printf("\n%s:\n", map->string);
	
	for (err = bpf_map_next(mdyn->mapfd, key, key); !err;
	     err = bpf_map_next(mdyn->mapfd, key, key)) {
		err = bpf_map_lookup(mdyn->mapfd, key, val);
		if (err)
			return;

		node_dump(rec, key);
		fputs("\t", stdout);
		node_dump(map, val);
		fputs("\n", stdout);
	}
}

int map_setup(node_t *script)
{
	mdyn_t *mdyn;
	int dumpfd = 0xfd00;
	size_t ksize, vsize;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
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

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (mdyn->mapfd) {
			if (strcmp(mdyn->map->string, "printf"))
				map_dump(mdyn);
			
			close(mdyn->mapfd);
		}
	}

	return 0;
}
