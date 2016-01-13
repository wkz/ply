.PHONY: all clean

#CFLAGS ?= -O3 -Wall -Werror
CFLAGS ?= -O0 -g -Wall -Wextra -Werror -Wno-unused-parameter
# CFLAGS += -I.
CFLAGS += -I/home/wkz/code/github/troglobit/troglos/staging/include

HEADERS = dtl.h lang/ast.h fs-ebpf.h libbpf.h provider/provider.h
SRCS  = lang/lex.c lang/parse.c lang/ast.c
SRCS += provider/provider.c provider/kprobe.c provider/builtins.c
SRCS += dtl.c libbpf.c fs-sema.c fs-compile.c
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: dtl

%.o: %.c $(HEADERS)
	@echo "  CC     $@"
	@$(CC) $(CFLAGS) -c $< -o $@

lang/parse.c: lang/parse.y
	@echo "  BISON  $@"
	@bison -Wall -Werror --defines=lang/parse.h --output=$@ $<

lang/parse.h: lang/parse.c

lang/lex.c: lang/lex.l lang/parse.h
	@echo "  FLEX   $@"
	@flex --header-file=lang/lex.h --outfile=$@ $<

dtl: $(OBJS)
	@echo "  LINK   $@"
	@$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	@echo "  CLEAN"
	@rm lang/lex.[ch] lang/parse.[ch] $(OBJS) dtl 2>/dev/null || true

all: dtl
