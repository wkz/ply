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

#define EXIT INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define MOV(_dst, _src)     INSN(BPF_ALU64 | BPF_MOV | BPF_X, _dst, _src, 0, 0)
#define MOV_IMM(_dst, _imm) INSN(BPF_ALU64 | BPF_MOV | BPF_K, _dst, 0, 0, _imm)

#define ALU(_op, _dst, _src)     INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_X, _dst, _src, 0, 0)
#define ALU_IMM(_op, _dst, _imm) INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_K, _dst, 0, 0, _imm)

#define STW(_dst, _off, _imm)   INSN(BPF_ST | BPF_SIZE(BPF_W) | BPF_MEM, _dst, 0, _off, _imm)
#define STXDW(_dst, _off, _src) INSN(BPF_ST | BPF_SIZE(BPF_W) | BPF_MEM, _dst, _src, _off, 0)

struct sym;
struct symtable;
struct provider;
struct fs_node;

struct ebpf {
	struct provider *provider;
	struct symtable *st;

	struct fs_node  *parent;
	
	struct bpf_insn *ip;
	struct bpf_insn  prog[BPF_MAXINSNS];
};

struct ebpf *fs_compile(struct fs_node *probe, struct provider *provider);

#endif	/* _FS_EBPF_H */
