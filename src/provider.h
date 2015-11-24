#ifndef _PROVIDER_H
#define _PROVIDER_H

#include "fs-ast.h"
#include "fs-ebpf.h"

struct provider {
	const char *name;
	void *priv;
	
	int (*annotate)(struct provider *p, struct fs_node *n);
	int  (*compile)(struct provider *p, struct ebpf *e, struct fs_node *n);
	int    (*setup)(struct provider *p, struct ebpf *e, struct fs_node *n);
};


extern struct provider kprobe_provider;

#endif	/* _PROVIDER_H */
