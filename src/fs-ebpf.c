#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include "fs-ast.h"
#include "fs-ebpf.h"

#define RET_ON_ERR(_err, _fmt, ...)					\
	if (_err) {							\
		fprintf(stderr, "error(%d): " _fmt, _err, ##__VA_ARGS__); \
	}


static int ebpf_mov(struct ebpf *e, int dst, struct fs_node *n)
{
	switch (n->type) {
	case FS_INT:
		*(e->ip)++ = MOV_IMM(dst, n->integer);
		break;

	default:
		assert(0);
	}

	return 0;
}

struct ebpf *ebpf_init(struct ebpf *e)
{
	memset(e->prog, 0, sizeof(e->prog));
	e->ip = e->prog;
	return e;
}

int fs_compile(struct fs_node *n, struct ebpf *e)
{
	struct fs_node *c;
	int err = 0;

	switch (n->type) {
	case FS_PROBE:
		for (c = n->probe.stmts; !err && c; c = c->next)
			err = fs_compile(c, e);
		RET_ON_ERR(err, "probe (%s)\n", n->probe.pspecs->string);

		if ((e->ip - 1)->code != EXIT.code) {
			*(e->ip)++ = MOV_IMM(BPF_REG_0, 0);
			*(e->ip)++ = EXIT;
		}
		break;

	case FS_RETURN:
		err = fs_compile(n->ret, e);
		RET_ON_ERR(err, "return\n");

		ebpf_mov(e, BPF_REG_0, n->ret);
		*(e->ip)++ = EXIT;
		break;

	case FS_INT:
		/* nop */
		break;

	default:
		RET_ON_ERR(1, "unsupported node %d\n", n->type);
	}

	return 0;
}
