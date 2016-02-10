
bin_PROGRAMS += src/bin/examine

# examine

src_bin_examine_SOURCES = \
src/bin/examine_depends.c \
src/bin/examine_main.c \
src/bin/examine_trace.c \
src/bin/examine_view.c \
src/bin/examine_private.h

if HAVE_WIN32
src_bin_examine_SOURCES += src/bin/examine_sigcheck.c
endif

# Memcheck tool

if HAVE_WIN32
include src/bin/memcheck/Makefile.mk
endif

src_bin_examine_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-I$(top_srcdir)/src/bin \
@EXM_CPPFLAGS@

src_bin_examine_CFLAGS = @EXM_CFLAGS@

src_bin_examine_LDADD = src/lib/libexamine.la

if HAVE_GUI

# examine_depends

if HAVE_WIN32

bin_PROGRAMS += src/bin/examine_depends

src_bin_examine_depends_SOURCES = \
src/bin/examine_depends_gui.c

src_bin_examine_depends_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPACKAGE_BIN_DIR=\"$(bindir)\" \
@EXM_GUI_CFLAGS@ \
@EXM_CPPFLAGS@

#src_bin_examine_depends_CFLAGS = @EXM_CFLAGS@

src_bin_examine_depends_LDADD = \
src/lib/libexamine.la \
@EXM_GUI_LIBS@

endif

# examine_view

if HAVE_WIN32

bin_PROGRAMS += src/bin/examine_view

src_bin_examine_view_SOURCES = \
src/bin/examine_view_gui.c

src_bin_examine_view_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPACKAGE_BIN_DIR=\"$(bindir)\" \
@EXM_GUI_CFLAGS@ \
@EXM_CPPFLAGS@

#src_bin_examine_view_CFLAGS = @EXM_CFLAGS@

src_bin_examine_view_LDADD = \
src/lib/libexamine.la \
@EXM_GUI_LIBS@

endif

endif
