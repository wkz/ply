%define parse.error verbose

%{
#include <search.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs-ast.h"

extern int lineno;
extern int yylex(void);

struct fs_node fs;

void yyerror(const char *s)
{
	printf("error(%d): %s\n", lineno, s);
}

%}

/* Represents the many different ways we can access our data */
%union {
	struct fs_node *node;
	struct fs_probespec *spec;
	char *string;
	unsigned int integer;
}

/* Define our terminal symbols (tokens). This should
   match our tokens.l lex file. We also define the node type
   they represent.
 */
%token <string> TIDENT TSTR TCMP TASSOP TBINOP
%token <integer> TINT

/* Define the type of node our nonterminal symbols represent.
   The types refer to the %union declaration above. Ex: when
   we call an ident (defined by union type ident) we are really
   calling an (NIdentifier*). It makes the compiler happy.
 */
/* %type <ident> ident */
/* %type <expr> numeric expr  */
/* %type <varvec> func_decl_args */
/* %type <exprvec> call_args */
/* %type <block> program stmts block */
/* %type <stmt> stmt var_decl func_decl */
/* %type <token> comparison */
%type <node> probes probe block
%type <spec> probespec

/* Operator precedence for mathematical operators */
%left TBINOP
%right '!'

%start script

%%

script : probes { fs.type = FS_SCRIPT; fs.script.probes = $<node>1; }
;

probes : probe { $$ = $1; }
       | probes probe { insque($<node>2, $<node>1); }
;

probe : probespec block {
	$$ = calloc(1, sizeof(struct fs_node));
	$$->type = FS_PROBE;
	$$->probe.spec = $<spec>1;
	$$->probe.stmts = $<node>2;
};

probespec : TIDENT { $$ = calloc(1, sizeof(struct fs_probespec)); $$->spec = $1; }
          | probespec ',' TIDENT /* { insque($2, $1); } */
;

block : '{' stmts '}' { $$ = NULL; }
;

stmts : stmt
      | stmts ';' stmt
;

stmt : /* empty */
     | assign
     | expr
;

assign : lval TASSOP expr
;

lval : TIDENT
     | TIDENT '[' vargs ']'
;

expr : TINT
     | TSTR
     | TIDENT
     | binop
     | call
     | '!' expr
     | '(' expr ')'
;

binop : expr TBINOP expr
;

call : TIDENT '(' vargs ')'
;

vargs : /* empty */
      | expr
      | vargs ',' expr
;

%%

