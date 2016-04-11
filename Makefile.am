ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = --host=$(host_triplet)

MAINTAINERCLEANFILES = \
Makefile.in \
aclocal.m4 \
compile \
config.guess \
config.h.in \
config.h.in~ \
config.sub \
configure \
depcomp \
install-sh \
ltmain.sh \
missing \
$(distdir).tar.gz \
$(distdir).tar.bz2 \
m4/libtool.m4 \
m4/lt~obsolete.m4 \
m4/ltoptions.m4 \
m4/ltsugar.m4 \
m4/ltversion.m4

pkgdir = $(bindir)
lib_LTLIBRARIES =
pkg_LTLIBRARIES =
bin_PROGRAMS =
EXTRA_DIST =

include src/lib/Makefile.mk
include src/bin/Makefile.mk
include src/tests/Makefile.mk

EXTRA_DIST += \
autogen.sh \
COPYING \
THANKS \
TODO \
m4/exm_attribute.m4 \
visual_studio/config.h \
visual_studio/vc12/examine/examine.vcxproj \
visual_studio/vc12/examine/examine.vcxproj.filters \
visual_studio/vc12/examine.sln \
visual_studio/vc12/examine_test/examine_test.vcxproj \
visual_studio/vc12/examine_test/examine_test.vcxproj.filters \
visual_studio/vc12/libexamine/libexamine.vcxproj \
visual_studio/vc12/libexamine/libexamine.vcxproj.filters \
visual_studio/vc12/libexamine_memcheck/libexamine_memcheck.vcxproj \
visual_studio/vc12/libexamine_memcheck/libexamine_memcheck.vcxproj.filters \
visual_studio/vc12/libexamine_test/libexamine_test.vcxproj \
visual_studio/vc12/libexamine_test/libexamine_test.vcxproj.filters \
visual_studio/vc14/examine/examine.vcxproj \
visual_studio/vc14/examine/examine.vcxproj.filters \
visual_studio/vc14/examine.sln \
visual_studio/vc14/examine_test/examine_test.vcxproj \
visual_studio/vc14/examine_test/examine_test.vcxproj.filters \
visual_studio/vc14/libexamine/libexamine.vcxproj \
visual_studio/vc14/libexamine/libexamine.vcxproj.filters \
visual_studio/vc14/libexamine_memcheck/libexamine_memcheck.vcxproj \
visual_studio/vc14/libexamine_memcheck/libexamine_memcheck.vcxproj.filters \
visual_studio/vc14/libexamine_test/libexamine_test.vcxproj \
visual_studio/vc14/libexamine_test/libexamine_test.vcxproj.filters
