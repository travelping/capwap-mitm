dnl ##
dnl ##  Debugging Support
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CHECK_DEBUGGING
dnl ##

AC_DEFUN([AC_CHECK_DEBUGGING],[dnl
AC_ARG_ENABLE(debug,dnl
[  --enable-debug          build for debugging (default=no)],
[dnl
if test ".$ac_cv_prog_gcc" = ".yes"; then
    case "$CFLAGS" in
        *-O* ) ;;
           * ) CFLAGS="$CFLAGS -O2" ;;
    esac
    case "$CFLAGS" in
        *-g* ) ;;
           * ) CFLAGS="$CFLAGS -g" ;;
    esac
    case "$CFLAGS" in
        *-pipe* ) ;;
              * ) AC_COMPILER_OPTION(pipe, -pipe, -pipe, CFLAGS="$CFLAGS -pipe")
 ;;
    esac
    case $PLATFORM in
        *-*-freebsd*|*-*-solaris* ) CFLAGS="$CFLAGS -pedantic" ;;
    esac
    CFLAGS="$CFLAGS -Wall"
    WMORE="-Wshadow -Wpointer-arith -Wcast-align -Winline"
    WMORE="$WMORE -Wmissing-prototypes -Wmissing-declarations -Wnested-externs"
    AC_COMPILER_OPTION(wmore, -W<xxx>, $WMORE, CFLAGS="$CFLAGS $WMORE")
    AC_COMPILER_OPTION(wnolonglong, -Wno-long-long, -Wno-long-long, CFLAGS="$CFLAGS -Wno-long-long")
    AC_COMPILER_OPTION(fnostrictaliasing, -fno-strict-aliasing, -fno-strict-aliasing, CFLAGS="$CFLAGS -fno-strict-aliasing")
else
    case "$CFLAGS" in
        *-g* ) ;;
           * ) CFLAGS="$CFLAGS -g" ;;
    esac
fi
msg="enabled"
AC_DEFINE(DEBUG, 1, [define to enable debugging])
],[
if test ".$ac_cv_prog_gcc" = ".yes"; then
case "$CFLAGS" in
    *-pipe* ) ;;
          * ) AC_COMPILER_OPTION(pipe, -pipe, -pipe, CFLAGS="$CFLAGS -pipe") ;;
esac
fi
case "$CFLAGS" in
    *-g* ) CFLAGS=`echo "$CFLAGS" |\
                   sed -e 's/ -g / /g' -e 's/ -g$//' -e 's/^-g //g' -e 's/^-g$//'` ;;
esac
case "$CXXFLAGS" in
    *-g* ) CXXFLAGS=`echo "$CXXFLAGS" |\
                     sed -e 's/ -g / /g' -e 's/ -g$//' -e 's/^-g //g' -e 's/^-g$//'` ;;
esac
msg="disabled"
])dnl
AC_MSG_CHECKING(for compilation debug mode)
AC_MSG_RESULT([$msg])
])
