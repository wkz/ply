#define _GNU_SOURCE 		/* asprintf */
#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "xprobe.h"

int xprobe_stem(struct ply_probe *pb, char type, char *stem, size_t size)
{
	return snprintf(stem, size, "%c:%s/p%"PRIxPTR"_",
			type, pb->ply->group, (uintptr_t)pb);
}

int xprobe_create(FILE *ctrl, const char *stem, const char *func)
{
	int len = 

	fputs(stem, ctrl);
	fputs(func, ctrl);
	fputc( ' ', ctrl);
	fputs(func, ctrl);
	fputc('\n', ctrl);
	return strlen(stem) + 2 * strlen(func) + 2;
}

int xprobe_glob(struct ply_probe *pb, glob_t *gl)
{
	char *evglob;
	int err;

	asprintf(&evglob, TRACEPATH "events/%s/p%"PRIxPTR"_*",
		 pb->ply->group, (uintptr_t)pb);

	err = glob(evglob, 0, NULL, gl);
	free(evglob);
	return err ? -EINVAL : 0;
}

char *xprobe_func(struct ply_probe *pb, char *path)
{
	char *slash;

	path += strlen(TRACEPATH "events/");
	path += strlen(pb->ply->group);

	slash = strchr(path, '/');
	assert(slash);
	*slash = '\0';
	return path;
}
