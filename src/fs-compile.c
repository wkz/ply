#include <errno.h>
#include <string.h>

#include "dtl.h"
#include "fs-ast.h"
#include "fs-ebpf.h"
#include "provider.h"

int compile_walk(struct ebpf *e, struct fs_node *n, struct fs_dyn *dst);

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

int emit_node_to_reg(struct ebpf *e, struct fs_node *n, int reg)
{
	if (n->dyn->type != FS_INT)
		return -EINVAL;

	switch (n->dyn->loc.type) {
	case FS_LOC_REG:
		if (n->dyn->loc.reg == reg)
			return 0;
		emit(e, MOV(reg, n->dyn->loc.reg));
		return 0;
	case FS_LOC_STACK:
		emit(e, LDXDW(reg, n->dyn->loc.addr, BPF_REG_10));
		return 0;
	default:
		break;
	}

	return -EINVAL;
}

int emit_node_to_stack(struct ebpf *e, struct fs_node *n, ssize_t at)
{
	switch (n->dyn->loc.type) {
	case FS_LOC_REG:
		emit(e, STXDW(BPF_REG_10, at, n->dyn->loc.reg));
		return 0;
	default:
		break;
	}

	return -ENOSYS;
}

int compile_map_load(struct ebpf *e, struct fs_node *n)
{
	struct fs_node *varg;
	ssize_t i, offs;
	int err;

	offs = n->dyn->loc.addr + n->dyn->size;
	fs_foreach(varg, n->map.vargs) {
		err = emit_node_to_stack(e, varg, offs);
		if (err)
			return err;

		offs += varg->dyn->size;
	}

	/* lookup key */
	emit_ld_mapfd(e, BPF_REG_1, n->dyn->mapfd);
	emit(e, MOV(BPF_REG_2, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_2, n->dyn->loc.addr));
	emit(e, CALL(BPF_FUNC_map_lookup_elem));

	emit(e, JMP_IMM(FS_JEQ, BPF_REG_0, 0, 6));

	/* if key existed, copy it to the stack */
	emit(e, MOV(BPF_REG_1, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_1, n->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_2, n->dyn->size));
	emit(e, MOV(BPF_REG_3, BPF_REG_0));
	emit(e, CALL(BPF_FUNC_probe_read));
	emit(e, JMP_IMM(FS_JA, 0, 0, n->dyn->size / 4));

	/* else, zero stack area */
	for (i = 0; i < (ssize_t)n->dyn->size; i += 4)
		emit(e, STW_IMM(BPF_REG_10, n->dyn->loc.addr + i, 0));

	n->dyn->loc.type = FS_LOC_STACK;
	return 0;
}

struct walk_ctx {
	struct ebpf *e;
	struct fs_dyn *dst;
};

static int compile_walk_post(struct fs_node *n, void *_ctx)
{
	struct walk_ctx *ctx = _ctx;
	struct ebpf *e = ctx->e;
	/* struct fs_dyn *dst = ctx->dst; */
	int err = -ENOSYS, reg;

	_d("%s (%s)", fs_typestr(n->type), n->string ? : "<none>");

	switch (n->type) {
	case FS_INT:
		err = 0;
		break;

	case FS_STR:
		if (n->dyn->loc.type == FS_LOC_NOWHERE) {
			err = emit_push(e, n->dyn->loc.addr, n->string,
					n->dyn->size);
			if (err)
				return err;

			n->dyn->loc.type = FS_LOC_STACK;
		} else
			err = 0;
		
		break;

	case FS_NOT:
		switch (n->not->dyn->loc.type) {
		case FS_LOC_REG:
			reg = n->not->dyn->loc.reg;
			break;
		case FS_LOC_STACK:
			reg = BPF_REG_0;
			emit(e, LDXDW(reg, n->not->dyn->loc.addr, BPF_REG_10));
			break;
		default:
			return -EINVAL;
		}

		err = 0;
		emit(e, JMP_IMM(FS_JEQ, reg, 0, 2));
		emit(e, MOV_IMM(reg, 0));
		emit(e, JMP_IMM(FS_JA, 0, 0, 1));
		emit(e, MOV_IMM(reg, 1));
		n->dyn->loc.type = FS_LOC_REG;
		n->dyn->loc.reg = reg;
		break;

	case FS_MAP:
		err = compile_map_load(e, n);
		break;

	case FS_CALL:
		err = e->provider->compile(e->provider, e, n);
		break;
	default:
		_e("unsupported node %s", fs_typestr(n->type));
		break;
	}
	return err;
}

int compile_walk(struct ebpf *e, struct fs_node *n, struct fs_dyn *dst)
{
	struct walk_ctx ctx = { .e = e, .dst = dst };

	return fs_walk(n, NULL, compile_walk_post, &ctx);
}

int compile_pred(struct ebpf *e, struct fs_node *pred)
{
	int err;

	_d(">");

	if (!pred)
		return 0;

	err = compile_walk(e, pred, NULL);
	if (err)
		return err;

	switch (pred->dyn->loc.type) {
	case FS_LOC_REG:
		emit(e, JMP_IMM(FS_JNE, pred->dyn->loc.reg, 0, 2));
		break;
	case FS_LOC_STACK:
		emit(e, LDXDW(BPF_REG_0, pred->dyn->loc.addr, BPF_REG_10));
		emit(e, JMP_IMM(FS_JNE, BPF_REG_0, 0, 2));
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

int compile_assign(struct ebpf *e, struct fs_node *assign)
{
	struct fs_node *lval = assign->assign.lval, *expr = assign->assign.expr;
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
	case FS_INT:
		emit_node_to_reg(e, lval, BPF_REG_0);
		if (expr->type == FS_INT)
			emit(e, ALU_IMM(assign->assign.op, BPF_REG_0, expr->integer));
		else {
			if (expr->dyn->loc.type != FS_LOC_REG) {
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
	emit(e, ALU_IMM(FS_ADD, BPF_REG_2, lval->dyn->loc.addr + lval->dyn->size));
	emit(e, MOV(BPF_REG_3, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_3, lval->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_4, 0));
	emit(e, CALL(BPF_FUNC_map_update_elem));

	_d("<");
	return 0;
}

int compile_agg(struct ebpf *e, struct fs_node *agg)
{
	return 0;
}

int compile_return(struct ebpf *e, struct fs_node *ret)
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

int compile_stmt(struct ebpf *e, struct fs_node *stmt)
{
	switch (stmt->type) {
	case FS_CALL:
		return compile_walk(e, stmt, NULL);
	case FS_ASSIGN:
		return compile_assign(e, stmt);
	case FS_RETURN:
		return compile_return(e, stmt);
	case FS_BINOP:
	case FS_NOT:
	case FS_MAP:
	case FS_INT:
	case FS_STR:
		_e("%s: useless statement", stmt->string);
		return 0;
	default:
		_e("%s: unknown statement", stmt->string);
		return -EINVAL;
	}
}

struct ebpf *fs_compile(struct fs_node *p, struct provider *provider)
{
	struct ebpf *e;
	struct fs_node *stmt;
	int err;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	e->ip = e->prog;
	e->provider = provider;

	err = compile_pred(e, p->probe.pred);
	if (err) {
		_e("%s: unable to compile predicate (%d)", p->string, err);
		goto err_free;
	}

	fs_foreach(stmt, p->probe.stmts) {
		err = compile_stmt(e, stmt);
		if (err) {
			_e("%s: unable to compile statement (%d)", p->string, err);
			goto err_free;
		}

		if (!stmt->next)
			break;
	}

	if (stmt->type != FS_RETURN) {
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
