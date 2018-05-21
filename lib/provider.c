#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <ply/provider.h>

struct providers {
	struct provider **ps;
	size_t len;
} providers;

#define providers_foreach(_ps, _p) \
	for((_p) = (_ps)->ps; (_p) < &(_ps)->ps[(_ps)->len]; (_p)++)
#include <stdio.h>
struct provider *provider_get(const char *name)
{
	struct provider **p;
	char *search;

	search = strtok(strdup(name), ":");

	providers_foreach(&providers, p) {
		if (strstr((*p)->name, search) == (*p)->name)
			break;
	}

	free(search);
	return *p;
}

void provider_register(struct provider *p)
{
	assert(p);
	assert(p->probe);
	assert(p->sym_alloc);

	providers.ps = realloc(providers.ps,
				 ++providers.len * sizeof(*providers.ps));

	providers.ps[providers.len - 1] = p;
}
