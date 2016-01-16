#include <errno.h>
#include <string.h>

#include "ply.h"
#include "compile.h"
#include "lang/ast.h"
#include "provider/provider.h"

int compile_walk(struct ebpf *e, node_t *n, dyn_t *dst);

extern int dump;

int reg_get(struct ebpf *e)
{
	int reg;

	for (reg = BPF_REG_9; reg >= BPF_REG_6; reg--)
		if (!e->regs[reg])
			return reg;

	return -ENOMEM;
}

void reg_put(struct ebpf *e, int reg)
{
	e->regs[reg] = NULL;
}

void emit(struct ebpf *e, struct bpf_insn insn)
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

	*(e->ip)++ = insn;
}

int emit_push(struct ebpf *e, ssize_t at, void *data, size_t size)
{
	uint32_t *wdata = data;	/* TODO: ENSURE ALIGNMENT */
	size_t left = size / sizeof(*wdata);

	for (; left; left--, wdata++, at += sizeof(*wdata))
		emit(e, STW_IMM(BPF_REG_10, at, *wdata));

	return 0;
}

int emit_node_to_reg(struct ebpf *e, node_t *n, int reg)
{
	if (n->dyn->type != TYPE_INT)
		return -EINVAL;

	switch (n->dyn->loc.type) {
	case LOC_REG:
		if (n->dyn->loc.reg == reg)
			return 0;
		emit(e, MOV(reg, n->dyn->loc.reg));
		return 0;
	case LOC_STACK:
		emit(e, LDXDW(reg, n->dyn->loc.addr, BPF_REG_10));
		return 0;
	default:
		break;
	}

	return -EINVAL;
}

int emit_node_to_stack(struct ebpf *e, node_t *n, ssize_t at)
{
	ssize_t i, sz;

	switch (n->dyn->loc.type) {
	case LOC_REG:
		emit(e, STXDW(BPF_REG_10, at, n->dyn->loc.reg));
		return 0;
	case LOC_STACK:		
		for (i = 0, sz = n->dyn->size; sz >= 8; i += 8, sz -= 8) {
			emit(e, LDXDW(BPF_REG_0, n->dyn->loc.addr + i, BPF_REG_10));
			emit(e, STXDW(BPF_REG_10, at + i, BPF_REG_0));
		}

		if (sz > 0) {
			emit(e, LDXW(BPF_REG_0, n->dyn->loc.addr + i, BPF_REG_10));
			emit(e, STXW(BPF_REG_10, at + i, BPF_REG_0));
		}
		return 0;
	default:
		break;
	}

	return -ENOSYS;
}

int compile_map_load(struct ebpf *e, node_t *n)
{
	node_t *varg;
	ssize_t i, offs;
	int err;

	offs = n->dyn->loc.addr + n->dyn->size;
	node_foreach(varg, n->map.rec->rec.vargs) {
		err = emit_node_to_stack(e, varg, offs);
		if (err)
			return err;

		offs += varg->dyn->size;
	}

	/* zero stack area */
	for (i = 0; i < (ssize_t)n->dyn->size; i += 4)
		emit(e, STW_IMM(BPF_REG_10, n->dyn->loc.addr + i, 0));

	/* lookup key */
	emit_ld_mapfd(e, BPF_REG_1, n->dyn->mapfd);
	emit(e, MOV(BPF_REG_2, BPF_REG_10));
	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_2, n->dyn->loc.addr + n->dyn->size));
	emit(e, CALL(BPF_FUNC_map_lookup_elem));

	emit(e, JMP_IMM(JMP_JEQ, BPF_REG_0, 0, 5));

	/* if key existed, copy it to the stack */
	emit(e, MOV(BPF_REG_1, BPF_REG_10));
	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_1, n->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_2, n->dyn->size));
	emit(e, MOV(BPF_REG_3, BPF_REG_0));
	emit(e, CALL(BPF_FUNC_probe_read));

	n->dyn->loc.type = LOC_STACK;
	return 0;
}

struct walk_ctx {
	struct ebpf *e;
	dyn_t *dst;
};

static int compile_walk_post(node_t *n, void *_ctx)
{
	struct walk_ctx *ctx = _ctx;
	struct ebpf *e = ctx->e;
	/* struct dyn_t *dst = ctx->dst; */
	int err = -ENOSYS, reg;

	_d("%s (%s)", type_str(n->type), n->string ? : "<none>");

	switch (n->type) {
	case TYPE_INT:
		err = 0;
		break;

	case TYPE_STR:
		if (n->dyn->loc.type == LOC_NOWHERE) {
			err = emit_push(e, n->dyn->loc.addr, n->string,
					n->dyn->size);
			if (err)
				return err;

			n->dyn->loc.type = LOC_STACK;
		} else
			err = 0;
		
		break;

	case TYPE_NOT:
		switch (n->not->dyn->loc.type) {
		case LOC_REG:
			reg = n->not->dyn->loc.reg;
			break;
		case LOC_STACK:
			reg = BPF_REG_0;
			emit(e, LDXDW(reg, n->not->dyn->loc.addr, BPF_REG_10));
			break;
		default:
			return -EINVAL;
		}

		err = 0;
		emit(e, JMP_IMM(JMP_JEQ, reg, 0, 2));
		emit(e, MOV_IMM(reg, 0));
		emit(e, JMP_IMM(JMP_JA, 0, 0, 1));
		emit(e, MOV_IMM(reg, 1));
		n->dyn->loc.type = LOC_REG;
		n->dyn->loc.reg = reg;
		break;

	case TYPE_MAP:
		err = compile_map_load(e, n);
		break;

	case TYPE_CALL:
		err = e->provider->compile(e->provider, e, n);
		break;
	default:
		_e("unsupported node %s", type_str(n->type));
		break;
	}
	return err;
}

int compile_walk(struct ebpf *e, node_t *n, dyn_t *dst)
{
	struct walk_ctx ctx = { .e = e, .dst = dst };

	return node_walk(n, NULL, compile_walk_post, &ctx);
}

int compile_pred(struct ebpf *e, node_t *pred)
{
	int err;

	_d(">");

	if (!pred)
		return 0;

	err = compile_walk(e, pred, NULL);
	if (err)
		return err;

	switch (pred->dyn->loc.type) {
	case LOC_REG:
		emit(e, JMP_IMM(JMP_JNE, pred->dyn->loc.reg, 0, 2));
		break;
	case LOC_STACK:
		emit(e, LDXDW(BPF_REG_0, pred->dyn->loc.addr, BPF_REG_10));
		emit(e, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 2));
		break;
	default:
		_e("unknown predicate location");
		return -EINVAL;
	}

	emit(e, MOV_IMM(BPF_REG_0, 0));
	emit(e, EXIT);
	_d("<");
	return 0;
}

int compile_assign(struct ebpf *e, node_t *assign)
{
	node_t *lval = assign->assign.lval, *expr = assign->assign.expr;
	int err;

	_d(">");
	err = compile_walk(e, lval, NULL);
	if (err)
		return err;

	_d("-");
	err = compile_walk(e, expr, NULL);
	if (err)
		return err;

	switch (lval->dyn->type) {
	case TYPE_INT:
		emit_node_to_reg(e, lval, BPF_REG_0);
		if (expr->type == TYPE_INT)
			emit(e, ALU_IMM(assign->assign.op, BPF_REG_0, expr->integer));
		else {
			if (expr->dyn->loc.type != LOC_REG) {
				emit_node_to_reg(e, expr, BPF_REG_1);
				emit(e, ALU(assign->assign.op, BPF_REG_0, BPF_REG_1));
			} else {
				emit(e, ALU(assign->assign.op, BPF_REG_0, expr->dyn->loc.reg));
			}
		}

		emit(e, STXDW(BPF_REG_10, lval->dyn->loc.addr, BPF_REG_0));
		break;
	default:
		return -ENOSYS;
	}

	emit_ld_mapfd(e, BPF_REG_1, lval->dyn->mapfd);
	emit(e, MOV(BPF_REG_2, BPF_REG_10));
	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_2, lval->dyn->loc.addr + lval->dyn->size));
	emit(e, MOV(BPF_REG_3, BPF_REG_10));
	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_3, lval->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_4, 0));
	emit(e, CALL(BPF_FUNC_map_update_elem));

	_d("<");
	return 0;
}

int compile_agg(struct ebpf *e, node_t *agg)
{
	return 0;
}

int compile_return(struct ebpf *e, node_t *ret)
{
	_d(">");
	if (!ret) {
		emit(e, MOV_IMM(BPF_REG_0, 0));
	} else {

	}

	emit(e, EXIT);
	_d("<");
	return 0;
}

int compile_stmt(struct ebpf *e, node_t *stmt)
{
	switch (stmt->type) {
	case TYPE_CALL:
		return compile_walk(e, stmt, NULL);
	case TYPE_ASSIGN:
		return compile_assign(e, stmt);
	case TYPE_RETURN:
		return compile_return(e, stmt);
	case TYPE_BINOP:
	case TYPE_NOT:
	case TYPE_MAP:
	case TYPE_INT:
	case TYPE_STR:
		_e("%s: useless statement", stmt->string);
		return 0;
	default:
		_e("%s: unknown statement", stmt->string);
		return -EINVAL;
	}
}

struct ebpf *node_compile(node_t *p, struct provider *provider)
{
	struct ebpf *e;
	node_t *stmt;
	int err;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	e->ip = e->prog;
	e->provider = provider;

	/* context pointer is supplied in r1, store it in r9 */
	emit(e, MOV(BPF_REG_9, BPF_REG_1));

	err = compile_pred(e, p->probe.pred);
	if (err) {
		_e("%s: unable to compile predicate (%d)", p->string, err);
		goto err_free;
	}

	node_foreach(stmt, p->probe.stmts) {
		err = compile_stmt(e, stmt);
		if (err) {
			_e("%s: unable to compile statement (%d)", p->string, err);
			goto err_free;
		}

		if (!stmt->next)
			break;
	}

	if (stmt->type != TYPE_RETURN) {
		err = compile_return(e, NULL);
		if (err) {
			_e("unable to compile implicit return (%d)", err);
			goto err_free;
		}
	}

	return e;

err_free:
	free(e);
	return NULL;
}
