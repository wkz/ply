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

void dump_insn(struct bpf_insn insn)
{
	const char *name;

	switch (insn.code) {
	case BPF_ALU64 | BPF_MOV | BPF_X:
		fprintf(stderr, "\tmov\tr%d, r%d\n", insn.dst_reg, insn.src_reg);
		return;
	case BPF_ALU64 | BPF_MOV | BPF_K:
		fprintf(stderr, "\tmov\tr%d, #%s0x%x\n", insn.dst_reg,
			insn.imm < 0 ? "-" : "", insn.imm < 0 ? -insn.imm : insn.imm);
		return;

	case BPF_JMP | BPF_EXIT:
		fprintf(stderr, "\texit\n");

	case BPF_JMP | BPF_CALL:
		name = bpf_func_name(insn.imm);
		if (name)
			fprintf(stderr, "\tcall\t%s\n", name);
		else
			fprintf(stderr, "\tcall\t#%d\n", insn.imm);
		return;

	case BPF_ST | BPF_SIZE(BPF_W) | BPF_MEM:
		fprintf(stderr, "\tstw\t[r%d%s0x%x], #%s0x%x\n", insn.dst_reg,
			insn.off < 0 ? "-" : "", insn.off < 0 ? -insn.off : insn.off,
			insn.imm < 0 ? "-" : "", insn.imm < 0 ? -insn.imm : insn.imm);
		return;

	case BPF_STX | BPF_SIZE(BPF_DW) | BPF_MEM:
		fprintf(stderr, "\tstdw\t[r%d%s0x%x], r%d\n", insn.dst_reg,
			insn.off < 0 ? "-" : "", insn.off < 0 ? -insn.off : insn.off,
			insn.src_reg);
		return;

	case BPF_LDX | BPF_SIZE(BPF_B) | BPF_MEM:
		fprintf(stderr, "\tldb\tr%d, [r%d%s0x%x]\n", insn.dst_reg, insn.src_reg,
			insn.off < 0 ? "-" : "", insn.off < 0 ? -insn.off : insn.off);
		return;
	case BPF_LDX | BPF_SIZE(BPF_DW) | BPF_MEM:
		fprintf(stderr, "\tlddw\tr%d, [r%d%s0x%x]\n", insn.dst_reg, insn.src_reg,
			insn.off < 0 ? "-" : "", insn.off < 0 ? -insn.off : insn.off);
		return;

	default:
		break;
	}

	if (insn.code & BPF_JMP) {
		
	}
		
	
	fprintf(stderr, "\tdata\t0x%16.16" PRIx64 "\n", *((uint64_t *)&insn));
}

void emit(prog_t *prog, struct bpf_insn insn)
{
	if (dump) {
		dump_insn(insn);
		/* FILE *dasm = popen("ebpf-dasm >&2", "w"); */

		/* if (dasm) { */
		/* 	fwrite(&insn, sizeof(insn), 1, dasm); */
		/* 	pclose(dasm); */
		/* } else { */
		/* 	assert(0); */
		/* } */
	}

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
