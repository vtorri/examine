
lib_LTLIBRARIES += src/lib/libexamine.la

src_lib_libexamine_la_SOURCES = \
src/lib/examine_file.c \
src/lib/examine_list.c \
src/lib/examine_log.c \
src/lib/examine_main.c \
src/lib/examine_map.c \
src/lib/examine_pe.c \
src/lib/examine_str.c \
src/lib/Examine.h \
src/lib/examine_file.h \
src/lib/examine_list.h \
src/lib/examine_log.h \
src/lib/examine_main.h \
src/lib/examine_map.h \
src/lib/examine_pe.h \
src/lib/examine_str.h \
src/lib/examine_private_file.h \
src/lib/examine_private_log.h \
src/lib/examine_private_map.h \
src/lib/examine_private_process.h \
src/lib/examine_private_str.h

if HAVE_WIN32
src_lib_libexamine_la_SOURCES += \
src/lib/examine_injection.c \
src/lib/examine_process.c \
src/lib/examine_stack.c \
src/lib/examine_injection.h \
src/lib/examine_process.h \
src/lib/examine_stack.h
else
src_lib_libexamine_la_SOURCES += src/lib/examine_pe_unix.h
endif

src_lib_libexamine_la_CPPFLAGS = @EXM_CPPFLAGS@
src_lib_libexamine_la_CFLAGS = @EXM_CFLAGS@

if HAVE_WIN32
src_lib_libexamine_la_LIBADD = @EXM_LIBS@
else
src_lib_libexamine_la_LIBADD = -lrt
endif

src_lib_libexamine_la_LDFLAGS = -no-undefined -version-info @version_info@

src_lib_libexamine_la_LIBTOOLFLAGS = --tag=disable-static

EXTRA_DIST += src/lib/examine_stack_pdb.c
