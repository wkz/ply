.PHONY: all clean

CFLAGS ?= -O3 -Wall -Werror

HEADERS = fs-ast.h
SRCS = fs-lex.c fs-parse.c fs-ast.c dtl.c
OBJS = $(patsubst %.c, %.o, $(SRCS))

%.o: %.c $(HEADERS)
	@echo "  CC     $@"
	@$(CC) $(CFLAGS) -c $< -o $@

fs-parse.c: fs-parse.y
	@echo "  BISON  $@"
	@bison -Wall -Werror --defines=fs-parse.h --output=fs-parse.c $<

fs-parse.h: fs-parse.c

fs-lex.c: fs-lex.l fs-parse.h
	@echo "  FLEX   $@"
	@flex --outfile=$@ $<

dtl: $(OBJS)
	@echo "  LINK   $@"
	@$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	@echo "  CLEAN"
	@rm fs-lex.[oc] fs-parse.[och] $(OBJS) dtl 2>/dev/null || true

all: dtl
