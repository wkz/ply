#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <sys/queue.h>

#include "../lang/ast.h"
#include "../compile.h"

struct builtin {
	const char *name;

	int (*annotate)(struct provider *p, struct ebpf *e, node_t *n);
	int  (*compile)(struct provider *p, struct ebpf *e, node_t *n);
};

struct provider {
	TAILQ_ENTRY(provider) node;

	const char *name;
	void *priv;
	
	int (*annotate)(struct provider *p, struct ebpf *e, node_t *n);
	int  (*compile)(struct provider *p, struct ebpf *e, node_t *n);
	int    (*setup)(struct provider *p, struct ebpf *e, node_t *n);
};

struct provider *provider_find    (const char *name);
void             provider_register(struct provider *p);

int global_annotate(struct provider *p, struct ebpf *e, node_t *n);
int global_compile (struct provider *p, struct ebpf *e, node_t *n);

#endif	/* _PROVIDER_H */
