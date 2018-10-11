/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_ARCH_H
#define _PLY_ARCH_H

struct type;

/* fixed length integers */
extern struct type t_s8;
extern struct type t_u8;
extern struct type t_s16;
extern struct type t_u16;
extern struct type t_s32;
extern struct type t_u32;
extern struct type t_s64;
extern struct type t_u64;

/* a hardware register */
extern struct type t_reg_t;

/* layout of captured registers */
extern struct type t_pt_regs;

/* ABI mapping of registers to arguments/return value */
const char *arch_register_argument(int num);
const char *arch_register_pc      (void);
const char *arch_register_return  (void);

#endif	/* _PLY_ARCH_H */
