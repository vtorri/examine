
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
