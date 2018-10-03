lib_LTLIBRARIES       = libply.la

libply_la_CPPFLAGS    = -I $(top_srcdir)/include
libply_la_CFLAGS      = -Wall -Wextra -Wno-unused -Wno-unused-result -Wno-strict-aliasing
libply_la_LDFLAGS     = $(AM_LDFLAGS) -version-info 0:0:0

AM_YFLAGS = -d -Wall
AM_LFLAGS = --header-file=lexer.h

lexer.h: lexer.c
grammar.y: lexer.h

BUILT_SOURCES = grammar.h lexer.h

libply_la_SOURCES     = 	\
	arch/@host_cpu@.c	\
	\
	aux/kallsyms.c		\
	aux/perf_event.c	\
	aux/printxf.c		\
	aux/syscall.c		\
	aux/utils.c		\
	\
	built-in/built-in.c	\
	built-in/aggregation.c	\
	built-in/buffer.c	\
	built-in/flow.c		\
	built-in/math.c		\
	built-in/memory.c	\
	built-in/print.c	\
	built-in/proc.c		\
	\
	provider/xprobe.c	\
	provider/kprobe.c	\
	provider/kretprobe.c	\
	\
	compile.c		\
	func.c			\
	grammar.y		\
	ir.c			\
	lexer.l			\
	node.c			\
	provider.c		\
	sym.c			\
	type.c			\
	\
	libply.c

