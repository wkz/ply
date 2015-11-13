%option noyywrap

%{
#include <stdio.h>

#include "fs-parse.h"

#define SAVE_TOKEN yylval.string = strdup(yytext)

int lineno = 1;

%}

identifier	[:*_a-zA-Z][:*_a-zA-Z0-9]*
binop		[+\-*/|&%^]

%%

[ \r\t]			;
\n			{ lineno++; }
{identifier}		{ SAVE_TOKEN; return TIDENT; }
==|!=|<|<=|>=|>		{ SAVE_TOKEN; return TCMP; }
{binop}=|=|<<=|>>=	{ SAVE_TOKEN; return TASSOP; }
{binop}			{ SAVE_TOKEN; return TBINOP; }
[.,;+\-*/!()\[\]{}]	{ return *yytext; }
\"(\\.|[^\\"])*\"	{ yylval.string = strndup(&yytext[1], strlen(yytext) - 2); return TSTR; }
[0-9]+			{ yylval.integer = strtoul(yytext, NULL, 0); return TINT; }
0[xX][0-9a-fA-F]+	{ yylval.integer = strtoul(yytext, NULL, 0); return TINT; }

.                       { fprintf(stderr, "error(%d): unknown token\n", lineno); yyterminate(); }

%%
