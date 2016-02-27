AUTOMAKE_OPTIONS = subdir-objects
SUFFIXES         = .c .h .y
sbin_PROGRAMS    = ply
ACLOCAL_AMFLAGS  = -I ../m4
AM_YFLAGS        = -d -Wall
ply_CFLAGS       = -Wno-unused-parameter

lang/lex.h: lang/lex.c
lang/lex.c: lang/lex.l
	@echo "  LEX      $@"
	@flex --header-file=lang/lex.h --outfile=$@ $<

BUILT_SOURCES = lang/lex.h lang/parse.h
ply_SOURCES   = lang/lex.c lang/parse.y lang/ast.c
ply_SOURCES  += pvdr/builtins.c pvdr/printf.c pvdr/pvdr.c pvdr/kprobe.c
ply_SOURCES  += annotate.c bpf-syscall.c compile.c map.c ply.c utils.c

ply_SOURCES  += pvdr/arch-null.c
if ARCH_ARM
ply_SOURCES  += pvdr/arch-arm.c
endif
if ARCH_X86_64
ply_SOURCES  += pvdr/arch-x86_64.c
endif

clean-local:
	rm lang/lex.[ch] lang/parse.[ch]
