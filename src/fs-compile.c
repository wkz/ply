#include <errno.h>

#include "dtl.h"
#include "fs-ast.h"
#include "fs-ebpf.h"

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

/*
  r0: return value
  r1: n
  r2: left byte pointer
  r3: right byte pointer

strncmp:
	mov	r0, 0
	mov	r1, #LENGTH
	mov	r2, [r10]
	add	r2, LEFT
	mov	r3, [r10]
	add	r3, RIGHT

next:	jeq	r1, #0, done
	ldxb	r0, [r2]
	ldxb	r4, [r3]
	sub	r0, r4
	jeq	r4, #0, done
	jne	r0, #0, done
	sub	r1, #1
	add	r2, #1
	add	r3, #1
	ja	next
done:	

 */
void emit_strncmp(struct ebpf *e, ssize_t left, ssize_t right, size_t n)
{
	/* setup arguments */
	emit(e, MOV_IMM(BPF_REG_0, 0));
	emit(e, MOV_IMM(BPF_REG_1, n));
	emit(e, MOV(BPF_REG_2, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_2, left));
	emit(e, MOV(BPF_REG_3, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_3, left));

	/* check bounds */
	emit(e, JMP_IMM(FS_JEQ, BPF_REG_1, 0, 10));

	/* load next bytes */
	emit(e, LDXB(BPF_REG_0, BPF_REG_2));
	emit(e, LDXB(BPF_REG_4, BPF_REG_3));

	/* compare */
	emit(e, ALU(FS_SUB, BPF_REG_0, BPF_REG_4));
	emit(e, JMP_IMM(FS_JEQ, BPF_REG_4, 0, 6));
	emit(e, JMP_IMM(FS_JNE, BPF_REG_0, 0, 5));

	/* bytes equal, prepare next bytes */
	emit(e, ALU_IMM(FS_SUB, BPF_REG_1, 1));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_2, 1));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_3, 1));
	emit(e, JMP(FS_JA, 0, -9));
}

int compile_pred(struct ebpf *e, struct fs_node *pred)
{
	struct fs_node *l = pred->pred.left, *r = pred->pred.right;
	size_t strsz;
	int err;

	if (!pred)
		return 0;

	err =         compile_walk(e, l, -1);
	err = err ? : compile_walk(e, r, -1);
	if (err)
		return err;

	if (l->dyn->type == FS_STR) {
		size_t len;

		if (l->dyn->size)
			len = l->dyn->size;
		else if (r->dyn->size)
			len = r->dyn->size;
		else
			len = l->dyn->ssize;

		emit_strncmp(e, l->dyn->loc.addr, r->dyn->loc.addr, len);
		emit(e, JMP_IMM(pred->pred.jmp, BPF_REG_0, 0, 2));
	} else if (l->dyn->type == FS_INT) {
		if (l->type == FS_INT) {
			emit(e, MOV_IMM(BPF_REG_0, l->integer));
			l->dyn->loc.reg = 0;
		}

		if (r->type == FS_INT)
			emit(e, JMP_IMM(pred->pred.jmp, l->dyn->loc.reg, r->integer, 2));
		else
			emit(e, JMP(pred->pred.jmp, l->dyn->loc.reg, r->dyn->loc.reg, 2));
	} else {
		_e("unsupported type of predicate \"%s\"", fs_typestr(l->dyn->type));
		return -ENOSYS;
	}

	emit(e, MOV_IMM(BPF_REG_0, 0));
	emit(e, EXIT);
	return 0;
}

int compile_call(struct ebpf *e, struct fs_node *agg, struct fs_dyn *dst)
{
	return 0;
}

int compile_assign(struct ebpf *e, struct fs_node *assign)
{
	return 0;
}

int compile_agg(struct ebpf *e, struct fs_node *agg)
{
	return 0;
}

int compile_return(struct ebpf *e, struct fs_node *ret)
{
	if (!ret) {
		emit(e, MOV_IMM(BPF_REG_0, 0));
	} else {

	}

	emit(e, EXIT);
	return 0;
}

int compile_stmt(struct ebpf *e, struct fs_node *stmt)
{
	switch (stmt->type) {
	case FS_CALL:
		return compile_call(e, stmt, NULL);
	case FS_ASSIGN:
		return compile_assign(e, stmt);
	case FS_AGG:
		return compile_agg(e, stmt);
	case FS_RETURN:
		return compile_return(e, stmt);
	case FS_BINOP:
	case FS_NOT:
	case FS_MAP:
	case FS_VAR:
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
	struct fs_dyn *dyn;
	int err;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	e->ip = e->prog;
	e->provider = provider;

	for (dyn = p->parent->script.dyns; dyn; dyn = dyn->next)
		dyn->loc.type = FS_LOC_NOWHERE;

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
