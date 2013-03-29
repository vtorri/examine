
MAINTAINERCLEANFILES = Makefile.in

bin_PROGRAMS = examine examine_test

examine_SOURCES = examine_main.c

examine_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPACKAGE_BIN_DIR=\"$(bindir)\" \
@EXM_CFLAGS@

examine_test_SOURCES = examine_test.c
