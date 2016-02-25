/*
 * Copyright 2015-2016 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"

int arch_reg_width(void) 
{
	return sizeof(uint64_t);
}

const char *reg_names[] = {
	"r15",
	"r14",
	"r13",
	"r12",
	"bp",
	"bx",
	"r11",
	"r10",
	"r9",
	"r8",
	"ax",
	"cx",
	"dx",
	"si",
	"di",
	"orig_ax",
	"ip",
	"cs",
	"flags",
	"sp",
	"ss",

	NULL
};

int arch_reg_atoi(const char *name)
{
	int reg;

	for (reg = 0; reg_names[reg]; reg++) {
		if (!strcmp(reg_names[reg], name))
			return reg;
	}

	return -ENOENT;
}

int arch_reg_arg(int num)
{
	switch (num) {
	case 0: return arch_reg_atoi("di");
	case 1: return arch_reg_atoi("si");
	case 2: return arch_reg_atoi("dx");
	case 3: return arch_reg_atoi("r10");
	case 4: return arch_reg_atoi("r8");
	case 5: return arch_reg_atoi("r9");
	}

	return -ENOSYS;
}

int arch_reg_func(void) 
{
	return arch_reg_atoi("ip");
}
