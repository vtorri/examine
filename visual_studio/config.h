/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */


#ifndef EXAMINE_CONFIG_H__
#define EXAMINE_CONFIG_H__


/* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name clash */
#if defined(_MSC_VER)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <malloc.h>
# if defined(_DEBUG)
#  undef  _malloca
#  define _CRTDBG_MAP_ALLOC
#  include <crtdbg.h>
# endif
#endif

/* __attribute__ ((unused)) is not supported. */
#define EXM_UNUSED

/* Name of package */
#define PACKAGE "examine"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "vincent dot torri at gmail dot com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "examine"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "examine 0.0.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "examine"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.0.2"

/* Version number of package */
#define VERSION "0.0.2"


#endif /* EXAMINE_CONFIG_H__ */

