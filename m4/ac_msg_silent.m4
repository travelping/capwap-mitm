dnl ##
dnl ##  Do not display message for a command
dnl ##
dnl ##  configure.ac:
dnl ##    AC_MSG_SILENT(...)
dnl ##

m4_define(AC_FD_TMP, 9)
m4_define([AC_MSG_SILENT],[dnl
exec AC_FD_TMP>&AC_FD_MSG AC_FD_MSG>/dev/null
$1
exec AC_FD_MSG>&AC_FD_TMP AC_FD_TMP>&-
])
