
fs-parse.c: fs-parse.y
	@echo "  BISON  $@"
	@bison --defines=fs-parse.h --output=fs-parse.c $<

fs-parse.h: fs-parse.c

fs-lex.c: fs-lex.l fs-parse.h
	@echo "  FLEX   $@"
	@flex --outfile=$@ $<

dtl: fs-lex.c fs-parse.c fs-ast.c
	@echo "  BUILD  $@"
	@gcc -o dtl fs-lex.c fs-parse.c fs-ast.c dtl.c
