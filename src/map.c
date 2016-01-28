#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "ply.h"
#include "bpf-syscall.h"
#include "map.h"

void map_dump(mdyn_t *mdyn)
{
	node_t *map = mdyn->map, *rec = map->map.rec, *varg = rec->rec.vargs;
	char *key = calloc(1, rec->dyn.size), *val = malloc(map->dyn.size);
	int err;

	printf("\n%s:\n", map->string);
	
	for (err = bpf_map_next(mdyn->mapfd, key, key); !err;
	     err = bpf_map_next(mdyn->mapfd, key, key)) {
		err = bpf_map_lookup(mdyn->mapfd, key, val);
		if (err)
			return;

		switch (varg->dyn.type) {
		case TYPE_INT:
			printf("  %-20" PRId64, *((int64_t *)key));
			break;
		case TYPE_STR:
			printf("  %-*.*s", (int)varg->dyn.size, (int)varg->dyn.size, key);
			break;
		default:
			err = -EINVAL;
			continue;
		}

		switch (map->dyn.type) {
		case TYPE_INT:
			printf("  %-20" PRId64 "\n", *((int64_t *)val));
			break;
		case TYPE_STR:
			printf("  %-*.*s\n", (int)map->dyn.size, (int)map->dyn.size, val);
			break;
		default:
			err = -EINVAL;
			continue;
		}
	}
}

int map_setup(node_t *script)
{
	mdyn_t *mdyn;
	int dumpfd = 0xfd00;
	size_t ksize, vsize;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (debug) {
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

		mdyn->mapfd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, vsize, 256);
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

	if (debug)
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
