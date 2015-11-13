#include <stdio.h>

#include "fs-ast.h"

static void __indent(int indent)
{
	while(indent--)
		fputc(' ', stderr);
}

static void _fs_ast_dump(struct fs_node *n, int indent)
{
	struct fs_node *c;

	__indent(indent);

	switch (n->type) {
	case FS_SCRIPT:
		fprintf(stderr, "script\n");

		for (c = n->script.probes; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_PROBE:
		fprintf(stderr, "probe \n");
		break;

	default:
		fprintf(stderr, "!type:%d\n", n->type);
		break;
	}
}

void fs_ast_dump(struct fs_node *n)
{
	return _fs_ast_dump(n, 0);
}
