
if HAVE_WIN32

lib_LTLIBRARIES += src/tests/libexamine_test_dll.la
src_tests_libexamine_test_dll_la_SOURCES = \
src/tests/examine_test_dll.c \
src/tests/examine_test_dll.h

src_tests_libexamine_test_dll_la_CPPFLAGS = \
-I$(top_srcdir)/src/tests

src_tests_libexamine_test_dll_la_CFLAGS = \
@EXM_TEST_CFLAGS@

src_tests_libexamine_test_dll_la_LDFLAGS = -no-undefined -version-info @version_info@

src_tests_libexamine_test_dll_la_LIBTOOLFLAGS = --tag=disable-static

bin_PROGRAMS += src/tests/examine_test

src_tests_examine_test_SOURCES = src/tests/examine_test.c
src_tests_examine_test_CFLAGS = \
@EXM_TEST_CFLAGS@

src_tests_examine_test_LDADD = \
src/tests/libexamine_test_dll.la

endif
