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

ident		{uaz}{uazd}*
map		@{ident}*
pspec		{ident}:[*?:_.,/a-zA-Z0-9]*

%%
"/*"			comment(yyscanner);
#.*\n			{ lineno++; }
[ \r\t]			;

\n			{ lineno++; }
"nil"			{ return NIL; }
"if"			{ return IF; }
"else"			{ return ELSE; }
"unroll"		{ return UNROLL; }
"break"			{ return BREAK; }
"continue"		{ return CONTINUE; }
"return"		{ return RETURN; }

{pspec}			{ yylval->string = strdup(yytext); return PSPEC; }
{ident}			{ yylval->string = strdup(yytext); return IDENT; }
{map}			{ yylval->string = strdup(yytext); return MAP;   }

"<<" { return LSH; }
">>" { return RSH; }
"<=" { return LE; }
">=" { return GE; }
"==" { return EQ; }
"!=" { return NE; }

[=$.,;+\-*/%<>&\^|!()\[\]{}]	{ return *yytext; }
\"(\\.|[^\\"])*\"	{ yylval->string = strndup(&yytext[1], strlen(yytext) - 2); return STRING; }
[0-9]+			{ yylval->integer = strtoul(yytext, NULL, 0); return INT; }
0[xX][0-9a-fA-F]+	{ yylval->integer = strtoul(yytext, NULL, 0); return INT; }

.                       { fprintf(stderr, "error(%d): unknown token\n", lineno); yyterminate(); }

%%
