#ifndef _PLY_SYMTABLE_H
#define _PLY_SYMTABLE_H

#include <stdio.h>

#include <ply/ast.h>

typedef struct sym sym_t;

struct sym {
	sym_t *next, *prev;

	type_t type;
	char *name;

	dyn_t dyn;

	union {
		struct {
			node_t *map;
		} map;

		struct {
			node_t *probe;
			node_t *first, *last;
		} var;
	};
};

#define sym_foreach(_s, _in) for((_s) = (_in); (_s); (_s) = (_s)->next)

int sym_fdump(sym_t *s, FILE *fp);


typedef struct symtable {
	sym_t *syms;
} symtable_t;

int symtable_fdump(symtable_t *st, FILE *fp);

sym_t *symtable_get_stack(symtable_t *st);
int    symtable_ref_stack(symtable_t *st);

sym_t *symtable_get     (symtable_t *st, node_t *n);
int    symtable_populate(symtable_t *st, node_t *script);

#endif	/* _PLY_SYMTABLE_H */
