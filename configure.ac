AC_PREREQ(2.61)
AC_INIT(ply, v1-beta1, https://github.com/wkz/ply/issues)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/ply.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_PROG_CC
AC_PROG_YACC
AC_PROG_RANLIB
AC_PROG_INSTALL

AC_HEADER_STDC
AC_CHECK_HEADERS(assert.h ctype.h errno.h fnmatch.h getopt.h inttypes.h limits.h)
AC_CHECK_HEADERS(poll.h search.h signal.h stdint.h stdio.h stdlib.h string.h unistd.h)
AC_CHECK_HEADERS(linux/bpf.h linux/perf_event.h linux/version.h)
AC_CHECK_HEADERS(sys/ioctl.h sys/queue.h sys/socket.h sys/stat.h sys/syscall.h sys/types.h)

AC_ARG_WITH([kerneldir],
  [AS_HELP_STRING([--with-kerneldir=DIR], [Custom kernel to build against])],
  [kerneldir=$withval],
  [kerneldir=no])
AC_SUBST([kerneldir], [$kerneldir])
AM_CONDITIONAL([KERNEL_DIR], [test x$kerneldir != xno])

AC_CANONICAL_HOST
AC_SUBST([host_cpu], [$host_cpu])
AM_CONDITIONAL([ARCH_X86_64], [test x$host_cpu = xx86_64])
AM_CONDITIONAL([ARCH_ARM],    [test x$host_cpu = xarm])
AM_CONDITIONAL([ARCH_AARCH64], [test x$host_cpu = xaarch64])

AC_OUTPUT
