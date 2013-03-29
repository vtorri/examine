
MAINTAINERCLEANFILES = Makefile.in

pkgdir = $(bindir)
pkg_LTLIBRARIES = examine_dll.la

examine_dll_la_SOURCES = \
examine_dll.c \
examine_list.c \
examine_stacktrace.c \
examine_list.h \
examine_log.h \
examine_stacktrace.h

examine_dll_la_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPSAPI_VERSION=1 \
@EXM_CPPFLAGS@

examine_dll_la_LIBADD = -lpsapi -limagehlp @EXM_LIBS@

examine_dll_la_LDFLAGS = -no-undefined -module -avoid-version

examine_dll_la_LIBTOOLFLAGS = --tag=disable-static

EXTRA_DIST = examine_stacktrace_vc.c
