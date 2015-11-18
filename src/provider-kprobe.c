#include <errno.h>
#include <string.h>

#include "provider.h"

static int kprobes_annotate(struct provider *p, struct fs_node *n)
{
	if (!strcmp("pid", n->string)) {
		if (n->call.vargs)
			return -EINVAL;

		n->annot.type = FS_INT;
		n->annot.size = sizeof(n->integer);
		return 0;
	}

	return -ENOENT;
}

struct provider kprobe_provider = {
	.name = "kprobe",
	.annotate = kprobes_annotate,
};
