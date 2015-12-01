#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <sys/queue.h>

#include "fs-ast.h"
#include "fs-ebpf.h"

struct builtin {
	const char *name;

	int (*annotate)(struct provider *p, struct fs_node *n);
	int  (*compile)(struct provider *p, struct ebpf *e, struct fs_node *n);
};

int global_compile (struct provider *p, struct ebpf *e, struct fs_node *n);
int global_annotate(struct provider *p, struct fs_node *n);

struct provider {
	TAILQ_ENTRY(provider) node;

	const char *name;
	void *priv;
	
	int (*annotate)(struct provider *p, struct fs_node *n);
	int  (*compile)(struct provider *p, struct ebpf *e, struct fs_node *n);
	int    (*setup)(struct provider *p, struct ebpf *e, struct fs_node *n);
};

struct provider *provider_find(const char *name);

void provider_register(struct provider *p);

#endif	/* _PROVIDER_H */
