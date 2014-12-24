dnl ##
dnl ##  Support for $(S)
dnl ##
dnl ##  configure.ac:
dnl ##    AC_SRCDIR_PREFIX(<varname>)
dnl ##

AC_DEFUN([AC_SRCDIR_PREFIX],[
ac_prog=[$]0
changequote(, )dnl
ac_srcdir=`echo $ac_prog | sed -e 's%/[^/][^/]*$%%' -e 's%\([^/]\)/*$%\1%'`
changequote([, ])dnl
if test ".$ac_srcdir" = ".$ac_prog"; then
    ac_srcdir=""
elif test "x$ac_srcdir" = "x."; then
    ac_srcdir=""
else
    if test ".$CFLAGS" = .; then
        CFLAGS="-I$ac_srcdir"
    else
        CFLAGS="$CFLAGS -I$ac_srcdir"
    fi
    ac_srcdir="$ac_srcdir/"
fi
$1="$ac_srcdir"
AC_SUBST($1)
])dnl
