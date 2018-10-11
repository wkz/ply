/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

static int func_validate_expr(const struct func *func, struct node *n, int strict)
{
	struct tfield *f;
	struct node *arg;
	int fargs, nargs = 0;

	if (func->type->ttype != T_FUNC) {
		nargs = node_nargs(n);

		if (nargs) {
			fargs = type_nargs(func->type);
			goto too_many;
		}

		return 0;
	}

	for (f = func->type->func.args, arg = n->expr.args;
	     f && f->type && arg; f++, arg = arg->next, nargs++) {
		if ((!strict && (f->type->ttype == T_VOID))
		    || (!strict && !arg->sym->type)
		    || (!strict && (arg->sym->type->ttype == T_VOID))
		    || type_compatible(arg->sym->type, f->type))
			continue;

		_ne(n, "%O argument to '%N' is of type '%T', expected '%T'.\n",
		    nargs, n, arg->sym->type, f->type);
	}

	if ((!f || !f->type) && !arg)
		return 0;

	nargs = node_nargs(n);
	fargs = type_nargs(func->type);
	if (f && f->type) {
		_ne(n, "too few arguments to %N; expected%s %d, got %d.\n",
		    n, func->type->func.vargs? " at least" : "", fargs, nargs);
		return -EINVAL;
	}

	if (func->type->func.vargs)
		return 0;

too_many:
	_ne(n, "too many arguments to %N; expected %d, got %d.\n",
	    n, fargs, nargs);
	return -EINVAL;
}

int func_static_validate(const struct func *func, struct node *n)
{
	int err = 0;

	if (!func->type)
		goto check_callback;

	switch (n->ntype) {
	case N_EXPR:
		/* if (func->type->ttype != T_FUNC) { */
		/* 	_ne(n, "%N is not callable.\n", n); */
		/* 	return -EINVAL; */
		/* } */
		err = func_validate_expr(func, n, 0);
		break;

	/* case N_IDENT: */
	/* 	if (func->type->ttype == T_FUNC) { */
	/* 		_ne(n, "%N is a function.\n", n); */
	/* 		return -EINVAL; */
	/* 	} */
	/* 	break; */

	default:
		/* num, str. nothing to validate. */
		break;
	}

check_callback:
	if (!err && func->static_validate)
		err = func->static_validate(func, n);

	return err;
}

struct type *func_return_type(const struct func *func)
{
	if (!func->type)
		return NULL;

	if (func->type->ttype == T_FUNC)
		return func->type->func.type;

	return func->type;
}
