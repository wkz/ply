/*
 * Copyright 2017 Leo Yan <leo.yan@linaro.org>
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
	return sizeof(uint64_t);
}

const char *reg_names[] = {
	"x0",
	"x1",
	"x2",
	"x3",
	"x4",
	"x5",
	"x6",
	"x7",
	"x8",
	"x9",
	"x10",
	"x11",
	"x12",
	"x13",
	"x14",
	"x15",
	"x16",
	"x17",
	"x18",
	"x19",
	"x20",
	"x21",
	"x22",
	"x23",
	"x24",
	"x25",
	"x26",
	"x27",
	"x28",
	"x29",
	"x30",
	"sp",
	"pc",
	"pstate",

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
	if (num < 0 || num > 7)
		return -ENOSYS;

	return num;
}

int arch_reg_func(void)
{
	return arch_reg_atoi("pc");
}

int arch_reg_retval(void)
{
	return arch_reg_atoi("x0");
}
