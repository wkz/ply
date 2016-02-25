%option reentrant noyywrap never-interactive nounistd
%option bison-bridge

%{
#include <stdio.h>

#include "parse.h"

int lineno = 1;

static int input(yyscan_t scanner);

void comment(yyscan_t scanner)
{
	int this, last = 0;

	for (this = input(scanner);
	     this != EOF && !(this == '/' && last == '*');
	     last = this, this = input(scanner))
		if (this == '\n')
			lineno++;
}

#pragma GCC diagnostic ignored "-Wunused-function"
%}

uaz		[_a-zA-Z]
uazd		[_a-zA-Z0-9]

identifier	{uaz}{uazd}*
uidentifier     \${identifier}
pspec		{identifier}:[:*_a-zA-Z0-9]*
op		[+\-*|&%^]|<<|>>
cmp		[!=<>]=|<|>

%%
"/*"			comment(yyscanner);
#.*\n			{ lineno++; }
[ \r\t]			;

\n			{ lineno++; }
"nil"			{ return NIL; }
"return"		{ return RETURN; }

{pspec}			{ yylval->string = strdup(yytext); return PSPEC;  }
{identifier}		{ yylval->string = strdup(yytext); return IDENT;  }
{uidentifier}		{ yylval->string = strdup(yytext); return UIDENT; }

{op}|{cmp}		{ yylval->string = strdup(yytext); return OP;  }
{op}?=			{ yylval->string = strdup(yytext); return AOP; }

[$.,;+\-*/!()\[\]{}]	{ return *yytext; }
\"(\\.|[^\\"])*\"	{ yylval->string = strndup(&yytext[1], strlen(yytext) - 2); return STRING; }
[0-9]+			{ yylval->integer = strtoul(yytext, NULL, 0); return INT; }
0[xX][0-9a-fA-F]+	{ yylval->integer = strtoul(yytext, NULL, 0); return INT; }

.                       { fprintf(stderr, "error(%d): unknown token\n", lineno); yyterminate(); }

%%
