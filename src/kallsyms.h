
#ifndef __KALLSYMS_H
#define __KALLSYMS_H

#include <inttypes.h>

typedef struct ksym {
	uintptr_t start;
	uintptr_t end;
	char sym[0x40 - (sizeof(uintptr_t) * 2)];
} ksym_t;

typedef struct ksyms ksyms_t;

const ksym_t *ksym_get(ksyms_t *ks, uintptr_t addr);
ksyms_t *ksyms_new(void);

#endif	/* __KALLSYMS_H */
