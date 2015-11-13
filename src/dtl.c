#include <stdio.h>

#include "fs-ast.h"
#include "fs-parse.h"
#include "fs-lex.h"

struct fs_node *parse_file(FILE *fp)
{
	struct fs_node *script = NULL;
	yyscan_t scanner;
 
	if (yylex_init(&scanner))
		return NULL;

	yyset_in(fp, scanner);
	yyparse(&script, scanner);
 
	yylex_destroy(scanner); 
	return script;
}

int main(int argc, char **argv)
{
	struct fs_node *script;

	script = parse_file(stdin);
	if (!script)
		return 1;
	
	fs_ast_dump(script);
	fs_node_free(script);
	return 0;
}
