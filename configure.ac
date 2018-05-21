AC_PREREQ(2.61)
AC_INIT(ply, 2.0.0-beta1, https://github.com/wkz/ply/issues)
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects])
AM_SILENT_RULES([yes])

LT_INIT

AC_CONFIG_HEADER([include/ply/config.h])
AC_CONFIG_FILES([Makefile lib/Makefile src/Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LEX
AC_PROG_YACC
AM_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS(linux/bpf.h linux/perf_event.h linux/version.h)

AC_CANONICAL_HOST
AC_SUBST([host_cpu], [$host_cpu])

AC_OUTPUT
