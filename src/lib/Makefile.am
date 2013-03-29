
MAINTAINERCLEANFILES = Makefile.in

lib_LTLIBRARIES = libexamine.la

libexamine_la_SOURCES = \
examine_log.c \
examine_log.h

libexamine_la_LDFLAGS = -no-undefined -version-info @version_info@

libexamine_la_LIBTOOLFLAGS = --tag=disable-static

pkgdir = $(bindir)
pkg_LTLIBRARIES = examine_dll.la

examine_dll_la_SOURCES = \
examine_dll.c \
examine_list.c \
examine_overloads.c \
examine_stacktrace.c \
examine_list.h \
examine_private.h \
examine_stacktrace.h

examine_dll_la_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPSAPI_VERSION=1 \
@EXM_CPPFLAGS@

examine_dll_la_LIBADD = \
$(top_builddir)/src/lib/libexamine.la \
-lpsapi \
-limagehlp \
@EXM_LIBS@

examine_dll_la_LDFLAGS = -no-undefined -module -avoid-version

examine_dll_la_LIBTOOLFLAGS = --tag=disable-static

EXTRA_DIST = examine_stacktrace_vc.c
