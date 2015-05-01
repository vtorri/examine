
# Source code for the Memcheck module

src_bin_examine_SOURCES += \
src/bin/memcheck/examine_memcheck.c

# DLL injected by Memcheck tool

pkg_LTLIBRARIES += src/bin/memcheck/examine_dll.la

src_bin_memcheck_examine_dll_la_SOURCES = \
src/bin/memcheck/examine_dll.c \
src/bin/memcheck/examine_overloads.c \
src/bin/memcheck/examine_stacktrace2.c \
src/bin/memcheck/examine_dll.h \
src/bin/memcheck/examine_stacktrace.h

src_bin_memcheck_examine_dll_la_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPSAPI_VERSION=1 \
@EXM_CPPFLAGS@

src_bin_memcheck_examine_dll_la_CFLAGS = @EXM_CFLAGS@

src_bin_memcheck_examine_dll_la_LIBADD = \
src/lib/libexamine.la \
-limagehlp \
@EXM_LIBS@

src_bin_memcheck_examine_dll_la_LDFLAGS = -no-undefined -module -avoid-version

src_bin_memcheck_examine_dll_la_LIBTOOLFLAGS = --tag=disable-static

EXTRA_DIST += src/lib/examine_stacktrace_vc.c
