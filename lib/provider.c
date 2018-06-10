#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/provider.h>

struct provider *provider_get(const char *name)
{
	struct provider *p;
	char *search;

	search = strtok(strdup(name), ":");

	for (p = &__start_providers; p < &__stop_providers; p++) {
 		if (strstr(p->name, search) == p->name)
			break;
	}

	if (p == &__stop_providers)
		p = NULL;

	free(search);
	return p;
}
