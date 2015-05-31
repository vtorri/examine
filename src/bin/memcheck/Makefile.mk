
# Source code for the Memcheck module

src_bin_examine_SOURCES += \
src/bin/memcheck/examine_memcheck.c

# DLL injected by Memcheck tool

pkg_LTLIBRARIES += src/bin/memcheck/libexamine_memcheck.la

src_bin_memcheck_libexamine_memcheck_la_SOURCES = \
src/bin/memcheck/examine_memcheck_dll.c \
src/bin/memcheck/examine_memcheck_hook.c \
src/bin/memcheck/examine_memcheck_hook.h

src_bin_memcheck_libexamine_memcheck_la_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
@EXM_CPPFLAGS@

src_bin_memcheck_libexamine_memcheck_la_CFLAGS = @EXM_CFLAGS@

src_bin_memcheck_libexamine_memcheck_la_LIBADD = \
src/lib/libexamine.la \
-limagehlp \
@EXM_LIBS@

src_bin_memcheck_libexamine_memcheck_la_LDFLAGS = -no-undefined -module -avoid-version

src_bin_memcheck_libexamine_memcheck_la_LIBTOOLFLAGS = --tag=disable-static
