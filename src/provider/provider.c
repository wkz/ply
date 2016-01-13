#include <string.h>

#include "provider.h"

TAILQ_HEAD(providers, provider);
static struct providers provider_list = TAILQ_HEAD_INITIALIZER(provider_list);


struct provider *provider_find(const char *pspec)
{
	struct provider *p;
	char *colon;

	colon = strchr(pspec, ':');
	if (!colon)
		return NULL;
	
	TAILQ_FOREACH(p, &provider_list, node) {
		if (!strncmp(p->name, pspec, colon - pspec))
			return p;
	}

	return NULL;
}

void provider_register(struct provider *p)
{
	TAILQ_INSERT_TAIL(&provider_list, p, node);
}
