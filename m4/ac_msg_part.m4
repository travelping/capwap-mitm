dnl ##
dnl ##  Display Configuration Headers
dnl ##
dnl ##  configure.ac:
dnl ##    AC_MSG_PART(<text>)
dnl ##

AC_DEFUN([AC_MSG_PART],[dnl
if test ".$enable_subdir" != .yes; then
    AC_MSG_RESULT()
    AC_MSG_RESULT(${TB}$1:${TN})
fi
])dnl
