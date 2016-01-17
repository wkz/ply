#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <sys/queue.h>

#include "../lang/ast.h"
#include "../compile.h"

typedef struct pvdr {
	TAILQ_ENTRY(pvdr) node;

	const char *name;
	
	int (*annotate)(node_t *call);
	int  (*compile)(node_t *call,  struct ebpf *e);
	int    (*setup)(node_t *probe, struct ebpf *e);
} pvdr_t;

pvdr_t *pvdr_find    (const char *name);
int     pvdr_resolve (node_t *script);
void    pvdr_register(pvdr_t *pvdr);


int builtin_annotate(node_t *call);
int builtin_compile (node_t *call, struct ebpf *e);

#endif	/* _PROVIDER_H */
