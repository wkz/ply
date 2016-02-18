%define parse.error verbose

%{
#include <stdio.h>

#include "ast.h"
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

%token RETURN
%token <string> PSPEC IDENT STRING OP AOP
%token <integer> INT

%type <node> script probes probe stmts stmt
%type <node> block expr variable record call vargs

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

stmt : variable AOP expr
		{ $$ = node_assign_new($1, $2, $3); }
     | variable '.' call
     		{ $$ = node_method_new($1, $3); }
     | expr
		{ $$ = $1; }
     | RETURN expr
		{ $$ = node_return_new($2); }
;

block : '{' stmts '}'
		{ $$ = $2; }
      | '{' stmts ';' '}'
		{ $$ = $2; }
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
;

variable : IDENT record
		{ $$ = node_map_new($1, $2); }
         | IDENT
        	{ $$ = node_var_new($1); }
;

record : '[' vargs ']'
		{ $$ = node_rec_new($2); }
;

call: IDENT '(' ')'
		{ $$ = node_call_new($1, NULL); }
    | IDENT '(' vargs ')'
		{ $$ = node_call_new($1, $3); }
;

vargs : expr
		{ $$ = $1; }
      | vargs ',' expr
		{ insque_tail($3, $1); }
;

%%

