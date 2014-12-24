ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

#   Makefile entry for upgrading GNU tools
upgrade-tools:
	libtoolize -f -c
	shtoolize -q all
