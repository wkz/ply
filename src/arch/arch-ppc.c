/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
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

#include <ply/arch.h>

int arch_reg_width(void)
{
	return sizeof(uint32_t);
}

const char *reg_names[] = {
	"gpr0",
	"gpr1",  /*Stack pointer.*/
	"gpr2",
	"gpr3", /* caller passing argument with gpr3-gpr10.*/
	"gpr4",
	"gpr5",
	"gpr6",
	"gpr7",
	"gpr8",
	"gpr9",
	"gpr10",
	"gpr11",
	"gpr12",
	"gpr13",
	"gpr14",
	"gpr15",
	"gpr16",
	"gpr17",
	"gpr18",
	"gpr19",
	"gpr20",
	"gpr21",
	"gpr22",
	"gpr23",
	"gpr24",
	"gpr25",
	"gpr26",
	"gpr27",
	"gpr28",
	"gpr29",
	"gpr30",
	"gpr31",
	"nip",
	"msr",
	"orig_gpr3",
	"ctr",
	"link",
	"xer",
	"ccr",
	"mq",
	"trap",
	"dar",
	"dsisr",
	"result",
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
	if (num < 0 || num > 6)
		return -ENOSYS;
	return num + 3;
}

int arch_reg_func(void)
{
	return arch_reg_atoi("nip");
}

int arch_reg_retval(void)
{
	return arch_reg_atoi("gpr3");
}
