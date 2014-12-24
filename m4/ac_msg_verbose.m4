dnl ##
dnl ##  Display a message under --verbose
dnl ##
dnl ##  configure.ac:
dnl ##    AC_MSG_VERBOSE(<text>)
dnl ##

m4_define([AC_MSG_VERBOSE],[dnl
if test ".$verbose" = .yes; then
    AC_MSG_RESULT([  $1])
fi
])
