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

%define parse.error verbose

%{
#include <stdio.h>

#include <ply/ast.h>

#include "parse.h"
#include "lex.h"

extern int lineno;

void yyerror(node_t **node, yyscan_t scanner, const char *s)
{
	fprintf(stderr, "error(%d): %s\n", lineno, s);
}

%}

%union {
	node_t *node;
	char *string;
	int64_t integer;
}
%code requires {

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

struct node;
typedef struct node node_t;

}
 
%define api.pure
%lex-param   { yyscan_t scanner }
%parse-param { node_t **script }
%parse-param { yyscan_t scanner }

%token NIL UNROLL RETURN
%token <string> PSPEC IDENT MAP STRING OP
%token <integer> INT

%type <node> script probes probe stmts stmt block unroll
%type <node> expr variable map record call mcall vargs

%left OP
%precedence '!'

%start script

%%

script : probes
		{ *script = node_script_new($1); }
;

probes : probe
		{ $$ = $1; }
       | probes probe
		{ insque_tail($2, $1); }
;

probe : PSPEC block
		{ $$ = node_probe_new($1, NULL, $2); }
      | PSPEC '/' expr '/' block
		{ $$ = node_probe_new($1, $3, $5); }
;

stmts : stmt
		{ $$ = $1; }
      | stmts ';' stmt
		{ insque_tail($3, $1); }
;

stmt : variable '=' expr
		{ $$ = node_assign_new($1, $3); }
     | map '=' NIL
		{ $$ = node_assign_new($1, NULL); }
     | map '.' call
     		{ $$ = node_method_new($1, $3); }
     | expr
		{ $$ = $1; }
     | unroll
		{ $$ = $1; }
     | RETURN expr
		{ $$ = node_return_new($2); }
;

block : '{' stmts '}'
		{ $$ = $2; }
      | '{' stmts ';' '}'
		{ $$ = $2; }
;

unroll : UNROLL '(' INT ')' block
		{ $$ = node_unroll_new($3, $5); }
;

expr : INT
		{ $$ = node_int_new($1); }
     | STRING
		{ $$ = node_str_new($1); }
     | record
		{ $$ = $1; }
     | expr OP expr
     		{ $$ = node_binop_new($1, $2, $3); }
     | '!' expr
		{ $$ = node_not_new($2); }
     | '(' expr ')'
		{ $$ = $2; }
     | variable
		{ $$ = $1; }
     | call
		{ $$ = $1; }
     | mcall
		{ $$ = $1; }
;

variable : IDENT
        	{ $$ = node_var_new($1); }
         | map
		{ $$ = $1; }
;

map : MAP record
		{ $$ = node_map_new($1, $2); }
;

record : '[' vargs ']'
		{ $$ = node_rec_new($2); }
;

call : IDENT '(' ')'
		{ $$ = node_call_new(NULL, $1, NULL); }
     | IDENT '(' vargs ')'
		{ $$ = node_call_new(NULL, $1, $3); }
;

mcall : IDENT '.' IDENT '(' ')'
		{ $$ = node_call_new($1, $3, NULL); }
      | IDENT '.' IDENT '(' vargs ')'
		{ $$ = node_call_new($1, $3, $5); }

vargs : expr
		{ $$ = $1; }
      | vargs ',' expr
		{ insque_tail($3, $1); }
;

%%

