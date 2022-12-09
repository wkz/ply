sbin_PROGRAMS = ply

ply_CPPFLAGS = -include $(top_builddir)/config.h -I $(top_srcdir)/include
ply_LDADD    = ../libply/libply.la
ply_SOURCES  = ply.c self-test.sh

BUILT_SOURCES = self-test.bytes

self-test.bytes: self-test.sh
	od -A n -t u1 <$<  | sed -e 's/\([0-9]\+\)/\1,/g' >$@
