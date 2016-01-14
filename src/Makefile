.PHONY: all clean

#CFLAGS ?= -O3 -Wall -Werror
CFLAGS ?= -O0 -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS += -I/home/wkz/code/github/troglobit/troglos/staging/include

HEADERS = ply.h compile.h bpf-syscall.h lang/ast.h provider/provider.h
SRCS  = $(addprefix lang/, ast.c lex.c parse.c)
SRCS += $(addprefix provider/, builtins.c kprobe.c provider.c)
SRCS += annotate.c bpf-syscall.c compile.c ply.c 
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: ply

%.o: %.c $(HEADERS)
	@echo "  CC     $@"
	@$(CC) $(CFLAGS) -c $< -o $@

lang/parse.c: lang/parse.y
	@echo "  BISON  $@"
	@bison -Wall -Werror --defines=$(subst .c,.h,$@) --output=$@ $<

lang/lex.c: lang/lex.l lang/parse.c
	@echo "  FLEX   $@"
	@flex --header-file=$(subst .c,.h,$@) --outfile=$@ $<

ply: $(OBJS)
	@echo "  LINK   $@"
	@$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	@echo "  CLEAN"
	@rm lang/lex.[ch] lang/parse.[ch] $(OBJS) ply 2>/dev/null || true
