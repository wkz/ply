#ifndef _PROVIDER_H
#define _PROVIDER_H

#include "fs-ast.h"

struct provider {
	const char *name;
	void *priv;
	
	int (*annotate)(struct provider *p, struct fs_node *n);
};


extern struct provider kprobe_provider;

#endif	/* _PROVIDER_H */
