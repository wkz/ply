#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"

int arch_reg_width(void) 
{
	return sizeof(uint32_t);
}

const char *reg_names[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"fp",
	"ip",
	"sp",
	"lr",
	"pc",
	"cpsr",
	"orig_r0",

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

	return num;
}
