
bin_PROGRAMS += \
src/bin/examine \
src/bin/examine_depends \
src/bin/examine_view

# examine

src_bin_examine_SOURCES = \
src/bin/examine_depends.c \
src/bin/examine_main.c \
src/bin/examine_trace.c \
src/bin/examine_view.c \
src/bin/examine_private.h

if HAVE_WIN32
src_bin_examine_SOURCES += \
src/bin/examine_memcheck.c
endif

src_bin_examine_CPPFLAGS = \
-I$(top_srcdir)/src/lib \
-DPACKAGE_BIN_DIR=\"$(bindir)\" \
@EXM_CPPFLAGS@

src_bin_examine_CFLAGS = @EXM_CFLAGS@

src_bin_examine_LDADD = \
src/lib/libexamine.la

# examine_depends

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

# examine_view

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
