.PHONY: all clean

#CFLAGS ?= -O3 -Wall -Werror
CFLAGS ?= -O0 -g -Wall -Werror -I/home/wkz/code/github/troglobit/troglos/staging/include

HEADERS = fs-ast.h fs-ebpf.h provider.h
SRCS  = fs-lex.c fs-parse.c fs-ast.c fs-ebpf.c fs-ebpf-global.c
SRCS += provider.c provider-kprobe.c dtl.c
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: dtl

%.o: %.c $(HEADERS)
	@echo "  CC     $@"
	@$(CC) $(CFLAGS) -c $< -o $@

fs-parse.c: fs-parse.y
	@echo "  BISON  $@"
	@bison -Wall -Werror --defines=fs-parse.h --output=fs-parse.c $<

fs-parse.h: fs-parse.c

fs-lex.c: fs-lex.l fs-parse.h
	@echo "  FLEX   $@"
	@flex --header-file=fs-lex.h --outfile=$@ $<

dtl: $(OBJS)
	@echo "  LINK   $@"
	@$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	@echo "  CLEAN"
	@rm fs-lex.[och] fs-parse.[och] $(OBJS) dtl 2>/dev/null || true

all: dtl
