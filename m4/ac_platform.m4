dnl ##
dnl ##  Support for Platform IDs
dnl ##
dnl ##  configure.ac:
dnl ##    AC_PLATFORM(<variable>)
dnl ##

AC_DEFUN([AC_PLATFORM],[
if test ".$host" != .; then
    $1="$host"
else
    $1=`$ac_config_guess`
fi
$1=`$ac_config_sub $$1` || exit 1
AC_SUBST($1)
if test ".$enable_subdir" != .yes; then
    echo "Platform: ${TB}${$1}${TN}"
fi
])dnl
