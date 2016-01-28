.PHONY: all clean

ARCH ?= $(shell uname -m)

#CFLAGS ?= -O3 -Wall -Werror
CFLAGS ?= -O0 -g -Wall -Wextra -Werror -Wno-unused-parameter

HEADERS = ply.h compile.h bpf-syscall.h map.h lang/ast.h pvdr/arch.h pvdr/pvdr.h
SRCS  = $(addprefix lang/, lex.c parse.c ast.c)
SRCS += $(addprefix pvdr/, arch-null.c builtins.c printf.c pvdr.c kprobe.c)
SRCS += annotate.c bpf-syscall.c compile.c map.c ply.c utils.c 
ifeq ($(ARCH),arm)
SRCS += pvdr/arch-arm.c
endif

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
