/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_IR_H
#define _PLY_IR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <bits/wordsize.h>
#include <linux/bpf.h>

/* TODO: This is not exported in userspace headers for some reason */
#ifndef MAX_BPF_STACK
#define MAX_BPF_STACK 512
#endif

/* TODO: TEMP workaround for old headers */
#ifndef BPF_JLE
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#endif

#define INSN(_code, _dst, _src, _off, _imm)	\
	((struct bpf_insn) {			\
		.code  = _code,			\
		.dst_reg = _dst,		\
		.src_reg = _src,		\
		.off   = _off,			\
		.imm   = _imm			\
	})

#define MOV32     INSN(BPF_ALU | BPF_MOV | BPF_X, 0, 0, 0, 0)
#define MOV32_IMM(_imm) INSN(BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, _imm)

#define MOV64     INSN(BPF_ALU64 | BPF_MOV | BPF_X, 0, 0, 0, 0)
#define MOV64_IMM(_imm) INSN(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, _imm)

#define EXIT INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define CALL(_imm) INSN(BPF_JMP | BPF_CALL, 0, 0, 0, _imm)

#define JMP(_op, _off)     INSN(BPF_JMP | BPF_OP((_op)) | BPF_X, 0, 0, _off, 0)
#define JMP_IMM(_op, _imm, _off) INSN(BPF_JMP | BPF_OP((_op)) | BPF_K, 0, 0, _off, _imm)

#define ALU32(_op)     INSN(BPF_ALU | BPF_OP((_op)) | BPF_X, 0, 0, 0, 0)
#define ALU32_IMM(_op, _imm) INSN(BPF_ALU | BPF_OP((_op)) | BPF_K, 0, 0, 0, _imm)

#define ALU64(_op)     INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_X, 0, 0, 0, 0)
#define ALU64_IMM(_op, _imm) INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_K, 0, 0, 0, _imm)

#define STX(_width, _off) INSN(BPF_STX | BPF_SIZE(_width) | BPF_MEM, 0, 0, _off, 0)
#define ST_IMM(_width, _off, _imm) INSN(BPF_ST | BPF_SIZE(_width) | BPF_MEM, 0, 0, _off, _imm)
#define ST_XADD(_width, _off) INSN(BPF_STX | BPF_SIZE(_width) | BPF_XADD, 0, 0, _off, 0)

#define LDX(_width, _off) INSN(BPF_LDX | BPF_SIZE(_width) | BPF_MEM, 0, 0, _off, 0)
#define LDDW_IMM(_imm) INSN(BPF_LD | BPF_DW | BPF_IMM, 0, 0, 0, _imm)

#if __WORDSIZE == 64
#  define MOV MOV64
#  define MOV_IMM MOV64_IMM
#  define ALU ALU64
#  define ALU_IMM ALU64_IMM
#else
#  define MOV MOV32
#  define MOV_IMM MOV32_IMM
#  define ALU ALU32
#  define ALU_IMM ALU32_IMM
#endif

#define BPF_REG_BP BPF_REG_10

/* r0 is return value and r1-r5 are used for arguments */
#define BPF_REG_CALLER_SAVE 0x3f

static inline int bpf_width(size_t size)
{
	switch (size) {
	case 1: return BPF_B;
	case 2: return BPF_H;
	case 4: return BPF_W;
	case 8: return BPF_DW;
	}

	return -1;
}

struct sym;
struct type;

enum vitype {
	VI_INSN,
	VI_LDMAP,
	VI_LABEL,
	VI_COMMENT,
};

struct vinsn {
	enum vitype vitype;

	union {
		struct {
			struct bpf_insn bpf;
			uint16_t dst;
			uint16_t src;
		} insn;

		struct {
			uint16_t reg;
			struct sym *sym;
		} map;

		int16_t label;

		const char *comment;
	};
};

struct ir {
	struct vinsn *vi;
	size_t len;

	int16_t next_label;
	uint16_t next_reg;

	ssize_t sp;
};

enum irloc {
	LOC_IMM   = (1 << 0),
	LOC_REG   = (1 << 1),
	LOC_STACK = (1 << 2),
};


struct irstate {
	int loc;

	size_t   size;
	int32_t  stack;
	int32_t  imm;
	uint16_t reg;

	struct {
		int dot:1;
		int lval:1;
		int stack:1;
	} hint;
};

void insn_dump(struct bpf_insn insn, FILE *fp);
void vinsn_dump(struct vinsn *vi, FILE *fp);
void ir_dump(struct ir *ir, FILE *fp);

int16_t ir_alloc_label(struct ir *ir);

void ir_init_irs(struct ir *ir, struct irstate *irs, struct type *t);
void ir_init_sym(struct ir *ir, struct sym *sym);

void ir_emit_insn   (struct ir *ir, struct bpf_insn bpf, uint16_t dst, uint16_t src);
void ir_emit_ldmap  (struct ir *ir, uint16_t dst, struct sym *map);
void ir_emit_label  (struct ir *ir, int16_t label);
void ir_emit_comment(struct ir *ir, const char *comment);

static inline void ir_emit_ldbp(struct ir *ir, uint16_t dst, ssize_t offset)
{
	/* Always use 64-bit operations. Otherwise kernel will mark
	 * `dst` as invalid even if the underlying ISA is 32-bit. */
	ir_emit_insn(ir, MOV64, dst, BPF_REG_BP);
	ir_emit_insn(ir, ALU64_IMM(BPF_ADD, offset), dst, 0);
}

void ir_emit_sym_to_reg  (struct ir *ir, uint16_t dst, struct sym *src);
void ir_emit_reg_to_sym  (struct ir *ir, struct sym *dst, uint16_t src);
void ir_emit_sym_to_stack(struct ir *ir, ssize_t offset, struct sym *src);
void ir_emit_sym_to_sym  (struct ir *ir, struct sym *dst, struct sym *src);
void ir_emit_read_to_sym (struct ir *ir, struct sym *dst, uint16_t src);

void ir_emit_data  (struct ir *ir, ssize_t dst, const char *src, size_t size);
void ir_emit_memcpy(struct ir *ir, ssize_t dst, ssize_t src, size_t size);
void ir_emit_bzero (struct ir *ir, ssize_t offset, size_t size);

void ir_emit_perf_event_output(struct ir *ir,
			       struct sym *map, struct sym *regs, struct sym *ev);

struct ir *ir_new(void);

int ir_bpf_generate(struct ir *ir);
int ir_bpf_extract (struct ir *ir, struct bpf_insn **insnsp, int *n_insnsp);

#endif	/* _PLY_IR_H */
