#include <errno.h>
#include <string.h>

#include "ply.h"
#include "compile.h"
#include "lang/ast.h"
#include "pvdr/pvdr.h"

extern int dump;

void emit(prog_t *prog, struct bpf_insn insn)
{
	if (dump) {
		FILE *dasm = popen("ebpf-dasm >&2", "w");

		if (dasm) {
			fwrite(&insn, sizeof(insn), 1, dasm);
			pclose(dasm);
		} else {
			assert(0);
		}
	}

	*(prog->ip)++ = insn;
}

void push(prog_t *prog, node_t *n)
{
	uint32_t *wdata;
	ssize_t at;
	size_t left;

	if (n->dyn.loc == LOC_STACK)
		return;

	prog->sp -= n->dyn.size;
	n->dyn.addr = prog->sp;
	
	switch (n->dyn.loc) {
	case LOC_STACK:
		/* guarded above */
		break;
	case LOC_REG:
		emit(prog, STXDW(BPF_REG_10, n->dyn.addr, n->dyn.reg));
		break;
	case LOC_NOWHERE:
		switch (n->type) {
		case TYPE_INT:
			wdata = (uint32_t *)&n->integer;
			break;
		case TYPE_STR:
			wdata = (uint32_t *)n->string;
			break;
		default:
			_e("unable to push node of type %s", type_str(n->type));
			assert(0);
		}

		at = n->dyn.addr;
		left = n->dyn.size / sizeof(*wdata);
		for (; left; left--, wdata++, at += sizeof(*wdata))
			emit(prog, STW_IMM(BPF_REG_10, at, *wdata));

		break;
	}
	
}

static int compile_pre(node_t *n, void *_prog)
{
	prog_t *prog = _prog;

	(void)(prog);

	switch (n->type) {
	default:
		break;
	}
	return 0;
}

static int compile_post(node_t *n, void *_prog)
{
	prog_t *prog = _prog;

	(void)(prog);

	switch (n->type) {
	case TYPE_INT:
		if (n->parent->type != TYPE_REC)
			break;
		/* fall-through */
	case TYPE_STR:
		push(prog, n);
		break;

	default:
		break;
	}
	return 0;
}

static int compile_walk(node_t *n, prog_t *prog)
{
	return node_walk(n, compile_pre, compile_post, prog);
}

static int compile_pred(node_t *pred, prog_t *prog)
{
	int err;

	if (!pred)
		return 0;

	_d(">");

	err = compile_walk(pred, prog);
	if (err)
		return err;

	switch (pred->dyn.loc) {
	case LOC_REG:
		emit(prog, JMP_IMM(JMP_JNE, pred->dyn.reg, 0, 2));
		break;
	case LOC_STACK:
		emit(prog, LDXDW(BPF_REG_0, pred->dyn.addr, BPF_REG_10));
		emit(prog, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 2));
		break;
	case LOC_NOWHERE:
		if (pred->type != TYPE_INT) {
			_e("unknown predicate location");
			return -EINVAL;
		}

		if (pred->integer)
			emit(prog, JMP_IMM(JMP_JA, 0, 0, 2));
		break;
	}

	emit(prog, MOV_IMM(BPF_REG_0, 0));
	emit(prog, EXIT);
	_d("<");
	return 0;
}

prog_t *compile_probe(node_t *probe)
{
	prog_t *prog;
	node_t *stmt;
	int err;

	prog = calloc(1, sizeof(*prog));
	if (!prog)
		return NULL;

	prog->ip = prog->insns;

	_d("");

	/* context (pt_regs) pointer is supplied in r1 */
	emit(prog, MOV(BPF_REG_9, BPF_REG_1));

	err = compile_pred(probe->probe.pred, prog);
	if (err)
		goto err_free;

	node_foreach(stmt, probe->probe.stmts) {
		err = compile_walk(stmt, prog);
		if (err)
			goto err_free;

		if (!stmt->next)
			break;
	}
	
	if (stmt->type == TYPE_RETURN)
		return prog;

	emit(prog, MOV_IMM(BPF_REG_0, 0));
	emit(prog, EXIT);
	return prog;

err_free:
	free(prog);
	return NULL;
}
