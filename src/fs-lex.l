%option noyywrap

%{
#include <stdio.h>

#include "fs-parse.h"

int lineno = 1;

static int input(void);

void comment(void)
{
	int this, last = 0;

	for (this = input();
	     this != EOF && !(this == '/' && last == '*');
	     last = this, this = input())
		if (this == '\n')
			lineno++;
}

#pragma GCC diagnostic ignored "-Wunused-function"
%}

identifier	[:*_a-zA-Z][:*_a-zA-Z0-9]*
binop		[+\-*/|&%^]

%%
"/*"			comment();

[ \r\t]			;
\n			{ lineno++; }
"if"			{ return IF; }
"else"			{ return ELSE; }
"return"		{ return RETURN; }
{identifier}		{ yylval.string = strdup(yytext); return IDENT; }
==|!=|<|<=|>=|>		{ yylval.string = strdup(yytext); return CMP; }
{binop}=|=|<<=|>>=	{ yylval.string = strdup(yytext); return ASSIGNOP; }
{binop}			{ yylval.string = strdup(yytext); return BINOP; }
[.,;+\-*/!()\[\]{}]	{ return *yytext; }
\"(\\.|[^\\"])*\"	{ yylval.string = strndup(&yytext[1], strlen(yytext) - 2); return STRING; }
[0-9]+			{ yylval.integer = strtoul(yytext, NULL, 0); return INT; }
0[xX][0-9a-fA-F]+	{ yylval.integer = strtoul(yytext, NULL, 0); return INT; }

.                       { fprintf(stderr, "error(%d): unknown token\n", lineno); yyterminate(); }

%%
