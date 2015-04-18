
lib_LTLIBRARIES += src/lib/libexamine.la

src_lib_libexamine_la_SOURCES = \
src/lib/examine_file.c \
src/lib/examine_injection.c \
src/lib/examine_list.c \
src/lib/examine_log.c \
src/lib/examine_main.c \
src/lib/examine_map.c \
src/lib/examine_pe.c \
src/lib/examine_process.c \
src/lib/examine_str.c \
src/lib/examine_file.h \
src/lib/examine_injection.h \
src/lib/examine_list.h \
src/lib/examine_log.h \
src/lib/examine_main.h \
src/lib/examine_map.h \
src/lib/examine_pe.h \
src/lib/examine_process.h \
src/lib/examine_str.h

if !HAVE_WIN32
src_lib_libexamine_la_SOURCES += src/lib/examine_pe_unix.h
endif

src_lib_libexamine_la_CFLAGS = @EXM_CFLAGS@

if HAVE_WIN32
src_lib_libexamine_la_CFLAGS += -DPSAPI_VERSION=1
src_lib_libexamine_la_LIBADD = -lpsapi
endif

src_lib_libexamine_la_LDFLAGS = -no-undefined -version-info @version_info@

src_lib_libexamine_la_LIBTOOLFLAGS = --tag=disable-static

pkgdir = $(bindir)

if HAVE_WIN32

pkg_LTLIBRARIES += src/lib/examine_dll.la

src_lib_examine_dll_la_SOURCES = \
src/lib/examine_dll.c \
src/lib/examine_overloads.c \
src/lib/examine_stacktrace.c \
src/lib/examine_private.h \
src/lib/examine_stacktrace.h

src_lib_examine_dll_la_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPSAPI_VERSION=1 \
@EXM_CPPFLAGS@

src_lib_examine_dll_la_CFLAGS = @EXM_CFLAGS@

src_lib_examine_dll_la_LIBADD = \
src/lib/libexamine.la \
-limagehlp \
@EXM_LIBS@

src_lib_examine_dll_la_LDFLAGS = -no-undefined -module -avoid-version

src_lib_examine_dll_la_LIBTOOLFLAGS = --tag=disable-static

endif

EXTRA_DIST += src/lib/examine_stacktrace_vc.c
