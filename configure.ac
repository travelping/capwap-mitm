dnl ##
dnl ##  PROLOG
dnl ##

dnl #   standard Autoconf prolog

AC_PREREQ(2.59)

AC_INIT(capwap-mitm, [1.0])
AC_CONFIG_SRCDIR([src/capwap-mitm.c])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.9 foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_SRCDIR_PREFIX(srcdir_prefix)
AC_HEADLINE(dnl
TPOSS CAPWAP Data Path, dnl
[Copyright (c) 2014 Travelping GmbH <info@travelping.com>])
AM_CONFIG_HEADER(config.h)
AC_PREFIX_DEFAULT(/usr)
AC_PLATFORM(PLATFORM)

dnl ##
dnl ##  BUILD TOOLS
dnl ##

AC_MSG_PART(Build Tools)

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CPP
AC_DISABLE_SHARED
AC_PROG_INSTALL
AC_SET_MAKE
AC_CHECK_DEBUGGING

AC_MSG_PART(Configure libtool)
AM_PROG_LIBTOOL

dnl ##
dnl ##   MANDATORY PLATFORM ENVIRONMENT
dnl ##

AC_MSG_PART(Mandatory Platform Environment)

AC_HEADER_STDC
AC_ISC_POSIX
AC_C_BIGENDIAN

AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h])
AC_CHECK_FUNCS(strcpy strdup strcmp free malloc open read close fprintf)
AC_CHECK_LIBM

AM_MAINTAINER_MODE

AC_HEADER_ASSERT

AC_MSG_PART(required libraries)
AC_CHECK_LIB([ev], [event_init],, AC_MSG_ERROR(Required library ev missing))

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.0.0],, [AC_MSG_ERROR(Required GnuTLS missing)])

AC_CHECK_LIB([pcap],[pcap_create],, AC_MSG_ERROR(Required library libpcap missing))
AC_CHECK_HEADERS([pcap/pcap.h],, AC_MSG_ERROR(Required library libpcap missing))

AC_CONFIG_FILES([
        Makefile
        src/Makefile
])

AC_OUTPUT
