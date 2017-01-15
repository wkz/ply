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

#include <ply/arch.h>

int __attribute__ ((weak)) arch_reg_width(void) 
{
	return sizeof(uintptr_t);
}

int __attribute__ ((weak)) arch_reg_atoi(const char *name) 
{
	return -ENOSYS;
}

int __attribute__ ((weak)) arch_reg_arg(int num) 
{
	return -ENOSYS;
}

int __attribute__ ((weak)) arch_reg_func(void) 
{
	return -ENOSYS;
}

int __attribute__ ((weak)) arch_reg_retval(void)
{
	return -ENOSYS;
}
