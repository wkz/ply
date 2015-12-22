#ifndef _FS_EBPF_H
#define _FS_EBPF_H

#include <linux/bpf.h>

#define INSN(_code, _dst, _src, _off, _imm)	\
	((struct bpf_insn) {			\
		.code  = _code,			\
		.dst_reg = _dst,		\
		.src_reg = _src,		\
		.off   = _off,			\
		.imm   = _imm			\
	})

#define MOV(_dst, _src)     INSN(BPF_ALU64 | BPF_MOV | BPF_X, _dst, _src, 0, 0)
#define MOV_IMM(_dst, _imm) INSN(BPF_ALU64 | BPF_MOV | BPF_K, _dst, 0, 0, _imm)

#define EXIT INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define CALL(_imm) INSN(BPF_JMP | BPF_CALL, 0, 0, 0, _imm)
#define JMP(_op, _dst, _src, _off)     INSN(BPF_JMP | BPF_OP((_op)) | BPF_X, _dst, _src, _off, 0)
#define JMP_IMM(_op, _dst, _imm, _off) INSN(BPF_JMP | BPF_OP((_op)) | BPF_K, _dst, 0, _off, _imm)

#define ALU(_op, _dst, _src)     INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_X, _dst, _src, 0, 0)
#define ALU_IMM(_op, _dst, _imm) INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_K, _dst, 0, 0, _imm)

#define STW_IMM(_dst, _off, _imm) INSN(BPF_ST | BPF_SIZE(BPF_W) | BPF_MEM, _dst, 0, _off, _imm)
#define STXDW(_dst, _off, _src)   INSN(BPF_STX | BPF_SIZE(BPF_DW) | BPF_MEM, _dst, _src, _off, 0)

#define LDXB(_dst, _off, _src)  INSN(BPF_LDX | BPF_SIZE(BPF_B)  | BPF_MEM, _dst, _src, _off, 0)
#define LDXDW(_dst, _off, _src) INSN(BPF_LDX | BPF_SIZE(BPF_DW) | BPF_MEM, _dst, _src, _off, 0)

#define RET_ON_ERR(_err, _fmt, ...)					\
	if (_err) {							\
		fprintf(stderr, "error(%s:%d): " _fmt, __func__, _err,	\
			##__VA_ARGS__);					\
	}

struct provider;

struct ebpf {
	struct provider *provider;
	struct fs_dyn *regs[__MAX_BPF_REG];

	struct bpf_insn *ip;
	struct bpf_insn  prog[BPF_MAXINSNS];
};

/* ssize_t     symtable_reserve(struct symtable *st, size_t size); */
/* struct sym *symtable_get    (struct symtable *st, const char *name); */

void        emit    (struct ebpf *e, struct bpf_insn insn);
/* int         ebpf_push    (struct ebpf *e, ssize_t at, void *data, size_t size); */
/* struct reg *ebpf_reg_find(struct ebpf *e, struct fs_node *n); */
/* int         ebpf_reg_bind(struct ebpf *e, struct reg * r, struct fs_node *n); */
/* int         ebpf_reg_load(struct ebpf *e, struct reg *r, struct fs_node *n); */
/* void        ebpf_reg_put (struct ebpf *e, struct reg *r); */
/* struct reg *ebpf_reg_get (struct ebpf *e); */

struct ebpf *fs_compile(struct fs_node *probe, struct provider *provider);

#endif	/* _FS_EBPF_H */
