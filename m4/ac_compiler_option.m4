dnl ##
dnl ##  Check whether compiler option works
dnl ##
dnl ##  configure.ac:
dnl ##    AC_COMPILER_OPTION(<name>, <display>, <option>,
dnl ##                       <action-success>, <action-failure>)
dnl ##

AC_DEFUN([AC_COMPILER_OPTION],[dnl
AC_MSG_CHECKING(for compiler option $2)
AC_CACHE_VAL(ac_cv_compiler_option_$1,[
cat >conftest.$ac_ext <<EOF
int main() { return 0; }
EOF
${CC-cc} -c $CFLAGS $CPPFLAGS $3 conftest.$ac_ext 1>conftest.out 2>conftest.err
if test $? -ne 0 -o -s conftest.err; then
     ac_cv_compiler_option_$1=no
else
     ac_cv_compiler_option_$1=yes
fi
rm -f conftest.$ac_ext conftest.out conftest.err
])dnl
if test ".$ac_cv_compiler_option_$1" = .yes; then
    ifelse([$4], , :, [$4])
else
    ifelse([$5], , :, [$5])
fi
AC_MSG_RESULT([$ac_cv_compiler_option_$1])
])dnl
