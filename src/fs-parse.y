%define parse.error verbose

%{
#include <stdio.h>

#include "fs-ast.h"
#include "fs-parse.h"
#include "fs-lex.h"

extern int lineno;

void yyerror(struct fs_node **node, yyscan_t scanner, const char *s)
{
	printf("error(%d): %s\n", lineno, s);
}

%}

%union {
	struct fs_node *node;
	struct fs_probespec *spec;
	char *string;
	unsigned int integer;
}
%code requires {

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

}
 
%define api.pure
%lex-param   { yyscan_t scanner }
%parse-param { struct fs_node **script }
%parse-param { yyscan_t scanner }

%token IF ELSE RETURN
%token <string> IDENT STRING CMP ASSIGNOP BINOP
%token <integer> INT

%type <node> probes probe block stmts stmt if_stmt variable expr vargs
%type <spec> probespec

%left BINOP
%precedence '!'

%start script

%%

script : probes
		{ *script = fs_script_new($1); }
;

probes : probe
		{ $$ = $1; }
       | probes probe
		{ insque_tail($2, $1); }
;

probe : probespec block
		{ $$ = fs_probe_new($1, $2); }
;

probespec : IDENT
		{ $$ = fs_probespec_add(NULL, $1); }
	  | probespec ',' IDENT
		{ $$ = fs_probespec_add($1, $3); }
;

stmts : stmt
		{ $$ = $1; }
      | stmts ';' stmt
		{ insque_tail($3, $1); }
;

stmt : variable ASSIGNOP expr
		{ $$ = fs_assign_new($1, $2, $3); }
     | expr
		{ $$ = $1; }
     | if_stmt
		{ $$ = $1; }
     | RETURN expr
		{ $$ = fs_return_new($2); }
;

if_stmt : IF expr block ELSE block
		{ $$ = fs_cond_new($2, $3, $5); }
	| IF expr block
		{ $$ = fs_cond_new($2, $3, NULL); }
;

block : '{' stmts '}'
		{ $$ = $2; }
      | '{' stmts ';' '}'
		{ $$ = $2; }
;

expr : INT
		{ $$ = fs_int_new($1); }
     | STRING
		{ $$ = fs_str_new($1); }
     | variable
		{ $$ = $1; }
     | expr BINOP expr
		{ $$ = fs_binop_new($1, $2, $3); }
     | IDENT '(' ')'
		{ $$ = fs_call_new($1, NULL); }
     | IDENT '(' vargs ')'
		{ $$ = fs_call_new($1, $3); }
     | '!' expr
		{ $$ = fs_not_new($2); }
     | '(' expr ')'
		{ $$ = $2; }
;

variable : IDENT
		{ $$ = fs_var_new($1, NULL); }
         | IDENT '[' vargs ']'
		{ $$ = fs_var_new($1, $3); }
;

vargs : expr
		{ $$ = $1; }
      | vargs ',' expr
		{ insque_tail($3, $1); }
;

%%

