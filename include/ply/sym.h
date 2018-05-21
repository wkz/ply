#ifndef _PLY_SYM_H
#define _PLY_SYM_H

#include <stddef.h>
#include <stdint.h>

#include "ir.h"

struct func;
struct node;
struct type;

struct symtab;

struct sym {
	struct symtab *st;

	const char *name;
	const struct func *func;

	struct type *type;
	struct irstate irs;

	/* TODO: move to priv */
	int mapfd;

	void *priv;
};

struct symtab {
	struct sym **syms;
	size_t len;

	unsigned global:1;
};

#define symtab_foreach(_st, _sym) \
	for((_sym) = (_st)->syms; (_sym) < &(_st)->syms[(_st)->len]; (_sym)++)

struct sym *sym_alloc(struct symtab *st, struct node *n,
		      const struct func *func);

void sym_dump(struct sym *sym, FILE *fp);
void symtab_dump(struct symtab *st, FILE *fp);

#endif	/* _PLY_SYM_H */
