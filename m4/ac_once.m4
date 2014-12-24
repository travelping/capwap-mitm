dnl ##
dnl ##  Perform something only once
dnl ##
dnl ##  configure.ac:
dnl ##    AC_ONCE(<action>)
dnl ##

m4_define([AC_ONCE],[
ifelse(ac_once_$1, already_done, ,[
    m4_define(ac_once_$1, already_done)
    $2
])dnl
])
