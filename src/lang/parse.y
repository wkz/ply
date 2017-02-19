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

%token EQ NE LE GE LSH RSH
%token NIL IF ELSE UNROLL BREAK CONTINUE RETURN
%token <string> PSPEC IDENT MAP STRING
%token <integer> INT

%type <node> script probes probe oblock block stmts stmt assign
%type <node> expr iff unroll binop var map record call mcall vargs
%type <node> stmtb iffb unrollb

/* C operator precedence */
%left '|'
%left '^'
%left '&'
%left EQ NE
%left '<' LE GE '>'
%left LSH RSH
%left '+' '-'
%left '*' '/' '%'

/* C if-else associativity */
%right ')' ELSE

%precedence '!'

/* Don't allow any ambiguity in the grammar */
%expect 0

%start script
%%

script: probes { *script = node_script_new($1); }
;

probes: probe
      | probe probes { $$ = insque_head($1, $2); }
;

probe: PSPEC oblock              { $$ = node_probe_new($1, NULL, $2); }
     | PSPEC '/' expr '/' oblock { $$ = node_probe_new($1,   $3, $5); }
;

oblock: %empty { $$ = NULL; }
      | block
;

block: '{' stmts '}' { $$ = $2; }
;

stmts: stmt
     | stmt ';'
     | stmtb
     | stmt ';' stmts { $$ = insque_head($1, $3); }
     | stmtb    stmts { $$ = insque_head($1, $2); }
;

stmt: map '.' call { $$ = node_method_new($1, $3); }
    | BREAK        { $$ = node_new(TYPE_BREAK);    }
    | CONTINUE     { $$ = node_new(TYPE_CONTINUE); }
    | RETURN       { $$ = node_new(TYPE_RETURN);   }
    | assign
    | expr
    | iff
    | unroll
;

stmtb: iffb
     | unrollb
;

assign: var '=' expr { $$ = node_assign_new($1,   $3); }
      | map '=' expr { $$ = node_assign_new($1,   $3); }
      | map '=' NIL  { $$ = node_assign_new($1, NULL); }
;

expr: INT          { $$ = node_int_new($1); }
    | STRING       { $$ = node_str_new($1); }
    | '!' expr     { $$ = node_not_new($2); }
    | '(' expr ')' { $$ = $2; }
    | binop
    | call
    | map
    | mcall
    | record
    | var
;

iff: IF '(' expr ')' stmt           { $$ = node_if_new($3, $5, NULL); }
   | IF '(' expr ')' stmt ELSE stmt { $$ = node_if_new($3, $5,   $7); }
;

iffb: IF '(' expr ')' block            { $$ = node_if_new($3, $5, NULL); }
    | IF '(' expr ')' stmt  ELSE block { $$ = node_if_new($3, $5,   $7); }
    | IF '(' expr ')' block ELSE block { $$ = node_if_new($3, $5,   $7); }
;

unroll: UNROLL '(' INT ')' stmt { $$ = node_unroll_new($3, $5); }
;

unrollb: UNROLL '(' INT ')' block { $$ = node_unroll_new($3, $5); }
;

binop: expr '|' expr { $$ = node_binop_new($1, OP_OR,  $3); }
     | expr '^' expr { $$ = node_binop_new($1, OP_XOR, $3); }
     | expr '&' expr { $$ = node_binop_new($1, OP_AND, $3); }
     | expr EQ  expr { $$ = node_binop_new($1, OP_EQ,  $3); }
     | expr NE  expr { $$ = node_binop_new($1, OP_NE,  $3); }
     | expr '<' expr { $$ = node_binop_new($3, OP_GT,  $1); }
     | expr LE  expr { $$ = node_binop_new($3, OP_GE,  $1); }
     | expr GE  expr { $$ = node_binop_new($1, OP_GE,  $3); }
     | expr '>' expr { $$ = node_binop_new($1, OP_GT,  $3); }
     | expr LSH expr { $$ = node_binop_new($1, OP_LSH, $3); }
     | expr RSH expr { $$ = node_binop_new($1, OP_RSH, $3); }
     | expr '+' expr { $$ = node_binop_new($1, OP_ADD, $3); }
     | expr '-' expr { $$ = node_binop_new($1, OP_SUB, $3); }
     | expr '*' expr { $$ = node_binop_new($1, OP_MUL, $3); }
     | expr '/' expr { $$ = node_binop_new($1, OP_DIV, $3); }
     | expr '%' expr { $$ = node_binop_new($1, OP_MOD, $3); }
;

var: IDENT { $$ = node_var_new($1); }
;

map: MAP record { $$ = node_map_new($1, $2); }
   | MAP        { $$ = node_map_new($1, NULL); }
;

record: '[' vargs ']' { $$ = node_rec_new($2); }
;

call: IDENT '(' ')'       { $$ = node_call_new(NULL, $1, NULL); }
    | IDENT '(' vargs ')' { $$ = node_call_new(NULL, $1,   $3); }
;

mcall: IDENT '.' IDENT '(' ')'        { $$ = node_call_new($1, $3, NULL); }
     | IDENT '.' IDENT '(' vargs ')'  { $$ = node_call_new($1, $3,   $5); }
;

vargs: expr
     | vargs ',' expr { insque_tail($3, $1); }
;

%%

