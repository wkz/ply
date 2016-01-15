#include <errno.h>

#include "arch.h"

int __attribute__ ((weak)) arch_reg_atoi(const char *name) 
{
	return -ENOSYS;
}
