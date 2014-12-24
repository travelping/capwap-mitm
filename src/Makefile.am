AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
AM_CFLAGS = -D_GNU_SOURCE -Wall -Wno-strict-aliasing -g -funit-at-a-time -std=gnu99 \
	    $(LIBGNUTLS_CFLAGS) \
	    -I$(top_srcdir)/include/compat \
	    -I$(top_srcdir)/include

bin_PROGRAMS = capwap-mitm

capwap_mitm_SOURCES = capwap-mitm.c log.c
capwap_mitm_LDADD = $(LIBGNUTLS_LIBS)

DISTCLEANFILES = *~
