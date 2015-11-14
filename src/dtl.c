#include <stdio.h>

#include "fs-ast.h"
#include "fs-ebpf.h"
#include "fs-parse.h"
#include "fs-lex.h"

struct fs_node *fs_load(FILE *fp)
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
	struct ebpf *e;

	script = fs_load(stdin);
	if (!script)
		return 1;

	e = malloc(sizeof(*e));
	
	if (fs_compile(script->script.probes, ebpf_init(e))) {	
		fs_ast_dump(script);
	}

	free(e);
	fs_node_free(script);
	return 0;
}
