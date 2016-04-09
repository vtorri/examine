
### Version

m4_define([v_maj], [0])
m4_define([v_min], [0])
m4_define([v_mic], [4])
m4_define([v_rev], [0])

m4_define([examine_version], [v_maj.v_min.v_mic])
m4_define([examine_version_rc], [v_maj.v_min.v_mic.v_rev])

m4_define([lt_cur], m4_eval(v_maj + v_min))
m4_define([lt_rev], v_mic)
m4_define([lt_age], v_min)

AC_INIT([examine], [examine_version], [vincent dot torri at gmail dot com])
AC_PREREQ([2.60])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])
AH_TOP([
#ifndef EXAMINE_CONFIG_H__
#define EXAMINE_CONFIG_H__
])
AH_BOTTOM([
#endif /* EXAMINE_CONFIG_H__ */
])

AC_USE_SYSTEM_EXTENSIONS

AC_DEFINE_UNQUOTED([PACKAGE_VERSION_RC], "[examine_version_rc]", [Version number of package for resource file])

### If the host is ceGCC, we exit

AC_CANONICAL_HOST

have_win32="no"
have_memcheck="no"
have_trace="no"
case "$host_os" in
   cegcc* | mingw32ce*)
      AC_MSG_ERROR([Windows CE is not supported. Exiting...])
      ;;
   mingw*)
      have_win32="yes"
      have_memcheck="yes"
      have_trace="yes"
      ;;
   *)
    ;;
esac

AM_CONDITIONAL([HAVE_WIN32], [test "x${have_win32}" = "xyes"])


AM_INIT_AUTOMAKE([1.11 dist-bzip2 dist-xz subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

lt_cv_deplibs_check_method='pass_all'
LT_PREREQ([2.4])
LT_INIT([win32-dll disable-static])

VMAJ=v_maj
AC_SUBST([VMAJ])

version_info="lt_cur:lt_rev:lt_age"
AC_SUBST([version_info])

### configure options

AC_ARG_WITH([libbfd-prefix],
   [AS_HELP_STRING([--with-libbfd-prefix=DIR], [prefix of libbfd @<:@default=/usr/local@:>@])],
   [_exm_libbfd_prefix="${with_libbfd_prefix}"],
   [_exm_libbfd_prefix="/usr/local"])

### Needed information

### Checks for programs

AC_PROG_CC_C99
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG

### Checks for libraries

PKG_CHECK_MODULES([EXM_GUI], [elementary], [have_gui="yes"], [have_gui="no"])

AM_CONDITIONAL([HAVE_GUI], [test "x${have_gui}" = "xyes"])

### Checks for header files

### Checks for types

AC_CHECK_SIZEOF([void *])

### Checks for structures

### Checks for compiler characteristics

AC_C_BIGENDIAN

EXM_ATTRIBUTE_UNUSED

EXM_CFLAGS="-std=c99 -pedantic -Wall -Wextra -Wshadow -Wdeclaration-after-statement -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wpointer-arith -Wno-missing-field-initializers"
if test "x${have_win32}" = "xyes" ; then
   EXM_CFLAGS="${EXM_CFLAGS} -Wno-pedantic-ms-format"
fi

AC_SUBST([EXM_CFLAGS])

EXM_TEST_CFLAGS="${EXM_CFLAGS} -g3 -ggdb3 -O0 -fno-omit-frame-pointer"

AC_SUBST([EXM_TEST_CFLAGS])

### Checks for linker characteristics

### Checks for library functions

# bfd_init
if test "x${have_win32}" = "xyes" ; then
   AC_MSG_CHECKING([for bfd_init in libbfd])
   CPPFLAGS_save="${CPPFLAGS}"
   CPPFLAGS="${CPPFLAGS} -I${_exm_libbfd_prefix}/include"
   LIBS_save="${LIBS}"
   if test "x${ac_cv_sizeof_void_p}" = "x8" ; then
      LIBS="${LIBS} -L${_exm_libbfd_prefix}/lib64/ -lbfd -liberty -lintl -lz"
   else
      LIBS="${LIBS} -L${_exm_libbfd_prefix}/lib/ -lbfd -liberty -lintl -lz"
   fi
   AC_LINK_IFELSE(
      [AC_LANG_PROGRAM(
          [[
#include <bfd.h>
          ]],
          [[
bfd_init();
          ]])],
      [
       EXM_CPPFLAGS="-I${_exm_libbfd_prefix}/include"
       if test "x${ac_cv_sizeof_void_p}" = "x8" ; then
          EXM_LIBS="-L${_exm_libbfd_prefix}/lib64/ -lbfd -liberty -lintl -lz"
       else
          EXM_LIBS="-L${_exm_libbfd_prefix}/lib/ -lbfd -liberty -lintl -lz"
       fi
       _efl_have_bfd_init="yes"
      ],
      [_efl_have_bfd_init="no"])
   LIBS="${LIBS_save}"
   CPPFLAGS="${CPPFLAGS_save}"

   AC_MSG_RESULT([${_efl_have_bfd_init}])

   if test "x${_efl_have_bfd_init}" = "xno" ; then
      AC_MSG_ERROR([libbfd, libiberty and libintl are required from binutils. Use --with-libbfd-prefix to set their prefix.])
   fi
fi

have_sigcheck="no"
if test "x${have_win32}" = "xyes" ; then
   have_sigcheck="yes"
fi

AC_SUBST([EXM_CPPFLAGS])
AC_SUBST([EXM_LIBS])


### Checks for system services

AC_SYS_LARGEFILE


AC_CONFIG_FILES([
Makefile
])

AC_OUTPUT


#####################################################################
## Info

echo
echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE_NAME $PACKAGE_VERSION"
echo "------------------------------------------------------------------------"
echo
echo "Configuration Options Summary:"
echo
echo "  OS...................: ${host_os}"
echo
echo "Tools:"
echo "  Memcheck.............: ${have_memcheck}"
echo "  Trace................: ${have_trace}"
echo "  Depends..............: yes"
echo "    GUI................: ${have_gui}"
echo "  View.................: yes"
echo "    GUI................: ${have_gui}"
echo "  Sigcheck.............: ${have_sigcheck}"
echo
echo "Compilation............: make"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  EXM_CPPFLAGS.........: $EXM_CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  EXM_CFLAGS...........: $EXM_CFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo "  EXM_LIBS.............: $EXM_LIBS"
echo
echo "Installation...........: make install"
echo "  prefix...............: $prefix"
echo
