dnl ##
dnl ##  Profiling Support
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CHECK_PROFILING
dnl ##

AC_DEFUN([AC_CHECK_PROFILING],[dnl
AC_MSG_CHECKING(for compilation profile mode)
AC_ARG_ENABLE(profile,dnl
[  --enable-profile        build for profiling (default=no)],
[dnl
if test ".$ac_cv_prog_gcc" = ".no"; then
    AC_MSG_ERROR([profiling requires gcc and gprof])
fi
CFLAGS=`echo "$CFLAGS" | sed -e 's/-O2//g'`
CFLAGS="$CFLAGS -O0 -pg"
LDFLAGS="$LDFLAGS -pg"
msg="enabled"
],[
msg="disabled"
])dnl
AC_MSG_RESULT([$msg])
if test ".$msg" = .enabled; then
    enable_shared=no
fi
])
