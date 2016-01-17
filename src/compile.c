#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "ply.h"
#include "compile.h"
#include "lang/ast.h"
#include "pvdr/pvdr.h"

extern int dump;

static const char *bpf_func_name(enum bpf_func_id id)
{
	switch (id) {
	case BPF_FUNC_map_lookup_elem:
		return "map_lookup_elem";
	case BPF_FUNC_map_update_elem:
		return "map_update_elem";
	case BPF_FUNC_map_delete_elem:
		return "map_delete_elem";
	case BPF_FUNC_probe_read:
		return "probe_read";
	case BPF_FUNC_ktime_get_ns:
		return "ktime_get_ns";
	case BPF_FUNC_trace_printk:
		return "trace_printk";
	case BPF_FUNC_get_current_pid_tgid:
		return "get_current_pid_tgid";
	case BPF_FUNC_get_current_uid_gid:
		return "get_current_uid_gid";
	case BPF_FUNC_get_current_comm:
		return "get_current_comm";

	default:
		return NULL;
	}
}

void dump_reg(uint8_t reg, int16_t off)
{
	if (off < 0)
		fprintf(stderr, "[r%u - 0x%x]", reg, -off);
	else if (off > 0)
		fprintf(stderr, "[r%u + 0x%x]", reg, off);
	else
		fprintf(stderr, "r%u", reg);
}

void dump_size(uint8_t size)
{
	switch (BPF_SIZE(size)) {
	case BPF_B:
		fputs("b\t", stderr);
		break;
	case BPF_H:
		fputs("h\t", stderr);
		break;
	case BPF_W:
		fputs("w\t", stderr);
		break;
	case BPF_DW:
		fputs("dw\t", stderr);
		break;
	}
}		

void dump_insn(struct bpf_insn insn)
{
	static size_t ip = 0;

	const char *name;
	enum {
		OFF_NONE,
		OFF_DST,
		OFF_SRC,
		OFF_EXP,
	} off = OFF_NONE;
	

	fprintf(stderr, "%.3zx:\t", ip);
	ip += 8;

	switch (BPF_CLASS(insn.code)) {
	case BPF_LD:
	case BPF_LDX:
		off = OFF_SRC;
		fputs("ld", stderr);
		dump_size(insn.code);
		break;

	case BPF_ST:
	case BPF_STX:
		off = OFF_DST;
		fputs("st", stderr);
		dump_size(insn.code);
		break;

	case BPF_ALU64:
		switch (BPF_OP(insn.code)) {
		case BPF_MOV: fputs("mov\t", stderr); break;
		case BPF_ADD: fputs("add\t", stderr); break;
		case BPF_SUB: fputs("sub\t", stderr); break;
		case BPF_MUL: fputs("mul\t", stderr); break;
		case BPF_DIV: fputs("div\t", stderr); break;
		case BPF_OR : fputs("or\t",  stderr); break;
		case BPF_AND: fputs("and\t", stderr); break;
		case BPF_LSH: fputs("lsh\t", stderr); break;
		case BPF_RSH: fputs("rsh\t", stderr); break;
		case BPF_NEG: fputs("neg\t", stderr); break;
		case BPF_MOD: fputs("mod\t", stderr); break;
		case BPF_XOR: fputs("xor\t", stderr); break;
		}
		break;

	case BPF_JMP:
		off = OFF_EXP;

		switch (BPF_OP(insn.code)) {
		case BPF_EXIT:
			fputs("exit\n", stderr);
			return;
		case BPF_CALL:
			fputs("call\t", stderr);

			name = bpf_func_name(insn.imm);
			if (name)
				fprintf(stderr, "%s\n", name);
			else
				fprintf(stderr, "%d\n", insn.imm);
			return;
		case BPF_JA:
			fprintf(stderr, "ja\t%+d\n", insn.off);
			return;

		case BPF_JEQ: fputs("jeq\t", stderr); break;
		case BPF_JNE: fputs("jne\t", stderr); break;
		case BPF_JGT: fputs("jgt\t", stderr); break;
		case BPF_JGE: fputs("jge\t", stderr); break;
		default:
			goto unknown;
		}
		break;

	default:
		goto unknown;
	}

	dump_reg(insn.dst_reg, off == OFF_DST ? insn.off : 0);		
	fputs(", ", stderr);

	switch (BPF_SRC(insn.code)) {
	case BPF_K:
		fprintf(stderr, "#%s0x%x", insn.imm < 0 ? "-" : "",
			insn.imm < 0 ? -insn.imm : insn.imm);
		break;
	case BPF_X:
		dump_reg(insn.src_reg, off == OFF_SRC ? insn.off : 0);		
		break;
	}

	if (off == OFF_EXP) {
		fputs(", ", stderr);
		fprintf(stderr, "%+d", insn.off);
	}

	fputc('\n', stderr);
	return;

unknown:
	fprintf(stderr, "data\t0x%16.16" PRIx64 "\n", *((uint64_t *)&insn));
}

void emit(prog_t *prog, struct bpf_insn insn)
{
	if (dump)
		dump_insn(insn);

	*(prog->ip)++ = insn;
}

void emit_push(prog_t *prog, node_t *n)
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

	n->dyn.loc = LOC_STACK;
}

int emit_map_load(prog_t *prog, node_t *n)
{
	node_t *varg;
	size_t i;

	prog->sp -= n->dyn.size;
	n->dyn.addr = prog->sp;

	node_foreach(varg, n->map.rec->rec.vargs) {
		if (!varg->next)
			break;
	}

	/* lookup key */
	emit_ld_mapfd(prog, BPF_REG_1, node_map_get_fd(n));
	emit(prog, MOV(BPF_REG_2, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_2, varg->dyn.addr));
	emit(prog, CALL(BPF_FUNC_map_lookup_elem));

	emit(prog, JMP_IMM(JMP_JNE, BPF_REG_0, 0, (n->dyn.size / 8) + 1));

	/* if the key was not found, zero-fill value area */
	for (i = 0; i < (n->dyn.size / 8); i++)
		emit(prog, STXDW(BPF_REG_10, n->dyn.addr + i * 8, BPF_REG_0));

	emit(prog, JMP_IMM(JMP_JA, 0, 0, 5));

	/* if key existed, copy it to the stack */
	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, n->dyn.addr));
	emit(prog, MOV_IMM(BPF_REG_2, n->dyn.size));
	emit(prog, MOV(BPF_REG_3, BPF_REG_0));
	emit(prog, CALL(BPF_FUNC_probe_read));

	n->dyn.loc = LOC_STACK;
	return 0;
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
	int err = 0;

	(void)(prog);

	_d("> %s%s%s (%s/%s/%#zx)", n->string ? "" : "<",
	   n->string ? : type_str(n->type), n->string ? "" : ">",
	   type_str(n->type), type_str(n->dyn.type), n->dyn.size);

	switch (n->type) {
	case TYPE_INT:
		if (n->parent->type != TYPE_REC)
			break;
		/* fall-through */
	case TYPE_STR:
		emit_push(prog, n);
		break;

	case TYPE_REC:
		/* components are already pushed to the stack */
		break;

	case TYPE_MAP:
		err = emit_map_load(prog, n);
		if (err)
			break;
		
	default:
		break;
	}

	_d("< %s%s%s (%s/%s/%#zx)", n->string ? "" : "<",
	   n->string ? : type_str(n->type), n->string ? "" : ">",
	   type_str(n->type), type_str(n->dyn.type), n->dyn.size);

	return err;
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
