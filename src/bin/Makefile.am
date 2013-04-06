
MAINTAINERCLEANFILES = Makefile.in

lib_LTLIBRARIES = libexamine_test_dll.la
libexamine_test_dll_la_SOURCES = \
examine_test_dll.c \
examine_test_dll.h

libexamine_test_dll_la_LDFLAGS = -no-undefined -version-info @version_info@

libexamine_test_dll_la_LIBTOOLFLAGS = --tag=disable-static

bin_PROGRAMS = examine examine_test

examine_SOURCES = examine_main.c

examine_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPACKAGE_BIN_DIR=\"$(bindir)\" \
@EXM_CPPFLAGS@

examine_CFLAGS = @EXM_CFLAGS@

examine_LDADD = \
$(top_builddir)/src/lib/libexamine.la

examine_test_SOURCES = examine_test.c

examine_test_LDADD = \
$(top_builddir)/src/bin/libexamine_test_dll.la
