AC_PREREQ(2.61)
AC_INIT(ply, [m4_esyscmd_s(git describe --always --dirty)],
	     https://github.com/wkz/ply/issues)

AC_GNU_SOURCE
AM_INIT_AUTOMAKE(1.11 foreign subdir-objects)
AM_SILENT_RULES(yes)

LT_INIT

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	man/Makefile
	src/Makefile
	src/libply/Makefile
	src/ply/Makefile
])
AC_CONFIG_MACRO_DIRS(m4)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LEX
AC_PROG_YACC
AM_PROG_LIBTOOL

AC_CHECK_PROG(HAVE_RONN,ronn,yes)
AM_CONDITIONAL(HAVE_RONN, test "$HAVE_RONN" = "yes")

AC_HEADER_STDC
AC_CHECK_HEADERS(linux/bpf.h linux/perf_event.h linux/version.h)

AC_CONFIG_LIBOBJ_DIR(lib)
AC_REPLACE_FUNCS(qsort_r)

AC_CANONICAL_HOST
AC_SUBST(arch)

AS_CASE($host_cpu,
	arm*, arch=arm,
	mips*, arch=mips,
	arch=$host_cpu)

AC_OUTPUT
