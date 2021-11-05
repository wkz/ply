/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_TYPE_H
#define _PLY_TYPE_H

#include <stddef.h>
#include <stdio.h>

#include <linux/bpf.h>

struct sym;

struct ttdef {
	char *name;
	struct type *type;
};

struct tscalar {
	size_t size;
	unsigned unsignd:1;
	char *name;
};

struct tptr {
	struct type *type;
	unsigned bpf:1;
};

struct tarray {
	struct type *type;
	size_t len;
};

struct tmap {
	struct type *vtype;
	struct type *ktype;

	enum bpf_map_type mtype;
	size_t len;
};

struct tfield {
	char *name;
	struct type *type;

	size_t offset;

	/* TODO: bitfields */
	/* uint8_t bit_offset; */
	/* uint8_t bit_size; */
};

#define tfields_foreach(_f, _fields) \
	for ((_f) = (_fields); (_f)->type; (_f)++)

struct tfield *tfields_get(struct tfield *fields, const char *name);

struct tstruct {
	char *name;
	struct tfield *fields;

	size_t size;
	unsigned packed:1;
};

struct tfunc {
	struct type *type;
	struct tfield *args;

	unsigned vargs:1;
};

enum ttype {
	T_VOID,
	T_TYPEDEF,
	T_SCALAR,
	T_POINTER,
	T_ARRAY,
	T_MAP,
	T_STRUCT,
	/* T_UNION, TODO */
	T_FUNC,
};

struct type {
	enum ttype ttype;
	union {
		struct ttdef tdef;
		struct tscalar scalar;
		struct tptr ptr;
		struct tarray array;
		struct tmap map;
		struct tstruct sou;
		struct tfunc func;
	};

	int (*fprint)(struct type *t, FILE *fp, const void *data);
	void *priv;
	unsigned fprint_log2:1;
};

struct type *type_scalar_promote(struct type *t);
struct type *type_scalar_convert(struct type *a, struct type *b);

int type_equal     (struct type *a, struct type *b);
int type_compatible(struct type *a, struct type *b);

void type_dump     (struct type *t, const char *name, FILE *fp);
void type_dump_decl(struct type *t, FILE *fp);
void type_dump_decls(FILE *fp);

int type_fprint(struct type *t, FILE *fp, const void *data);
int type_cmp   (const void *a, const void *b, void *_type);

ssize_t type_alignof(struct type *t);
ssize_t type_offsetof(struct type *t, const char *field);
ssize_t type_sizeof(struct type *t);

void type_struct_layout(struct type *t);

int type_add(struct type *t);
int type_add_list(struct type **ts);

struct type *type_typedef (struct type *type, const char *name);
struct type *type_array_of(struct type *type, size_t len);
struct type *type_map_of  (struct type *ktype, struct type *vtype,
			   enum bpf_map_type mtype, size_t len);
struct type *type_ptr_of  (struct type *type, unsigned bpf);


/* built-in types */

extern struct type t_void;

extern struct type t_char;
extern struct type t_schar;
extern struct type t_uchar;

extern struct type t_short;
extern struct type t_sshort;
extern struct type t_ushort;

extern struct type t_int;
extern struct type t_sint;
extern struct type t_uint;

extern struct type t_long;
extern struct type t_slong;
extern struct type t_ulong;

extern struct type t_llong;
extern struct type t_sllong;
extern struct type t_ullong;

extern struct type t_binop_func;
extern struct type t_unary_func;
extern struct type t_vargs_func;

extern struct type t_buffer;

/* helpers */

static inline int type_nargs(struct type *t)
{
	struct tfield *f;
	int nargs = 0;

	if (!t->func.args)
		return 0;

	for (f = t->func.args; f->type; f++, nargs++);

	return nargs;

}

static inline struct type *type_base(struct type *t)
{
	while (t->ttype == T_TYPEDEF)
		t = t->tdef.type;

	return t;
}


static inline struct type *type_return(struct type *t)
{
	struct type *base = type_base(t);

	if (base->ttype == T_FUNC)
		return base->func.type;

	return t;
}

static inline int type_is_string(struct type *t)
{
	t = type_base(t);

	if (t->ttype != T_ARRAY)
		return 0;

	t = type_base(t->array.type);
	return t == &t_char;
}

#endif	/* _PLY_TYPE_H */
