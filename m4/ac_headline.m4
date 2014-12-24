dnl ##
dnl ##  Support for Configuration Headers
dnl ##
dnl ##  configure.ac:
dnl ##    AC_HEADLINE(<short-name>, <long-name>,
dnl ##                <vers-var>, <vers-file>,
dnl ##                <copyright>)
dnl ##

AC_DEFUN([AC_HEADLINE],[dnl
#   configuration header
if test ".`echo dummy [$]@ | grep enable-subdir`" != .; then
    enable_subdir=yes
fi
if test ".`echo dummy [$]@ | grep help`" = .; then
    #   bootstrapping shtool
    ac_prog=[$]0
changequote(, )dnl
    ac_srcdir=`echo $ac_prog | sed -e 's%/[^/][^/]*$%%' -e 's%\([^/]\)/*$%\1%'`
changequote([, ])dnl
    test ".$ac_srcdir" = ".$ac_prog" && ac_srcdir=.
    ac_shtool="${CONFIG_SHELL-/bin/sh} $ac_srcdir/shtool"

    #   find out terminal sequences
    if test ".$enable_subdir" != .yes; then
        TB=`$ac_shtool echo -n -e %B 2>/dev/null`
        TN=`$ac_shtool echo -n -e %b 2>/dev/null`
    else
        TB=''
        TN=''
    fi

    #   find out package version
    $3_STR="`$ac_shtool version -lc -dlong $ac_srcdir/$4`"
    AC_SUBST($3_STR)

    #   friendly header ;)
    if test ".$enable_subdir" != .yes; then
        echo "Configuring ${TB}$1${TN} ($2), Version ${TB}${$3_STR}${TN}"
        echo "$5"
    fi

    #   additionally find out hex version
    $3_HEX="`$ac_shtool version -lc -dhex $ac_srcdir/$4`"
    AC_SUBST($3_HEX)
fi
])dnl
