#include <stdio.h>

#include "fs-ast.h"

extern struct fs_node fs;

extern int yyparse(void);

int main(int argc, char **argv)
{
	int err = yyparse();

	fs_ast_dump(&fs);
	return err;
}
