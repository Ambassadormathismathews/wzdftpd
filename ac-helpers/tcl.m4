dnl   WZD_LIB_TCL()
dnl  
dnl   Search for a useable version of the TCL libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set WZD_TCL_INCLUDES and WZD_TCL_LIBS as
dnl   appropriate, and set the shell variable 'wzd_have_tcl' to
dnl   'yes'. Otherwise, set 'wzd_have_tcl' to 'no'.
dnl   
dnl   The macro will execute optional argument 1 if given, if TCL
dnl   libs are found.
dnl   
dnl   This macro alse checks for the '--with-tcl=PATH' flags;
dnl   if given, the macro will use the PATH specified, and the
dnl   configuration script will execute macro arg 2 if given.
dnl   
dnl   We cache the results of individual searches under particular
dnl   prefixes, not the overall result of whether we found TCL
dnl   That way, the user can re-run the configure script with
dnl   different --with-tcl switch values, without interference
dnl   from the cache.
dnl
dnl   TODO check TCL version

AC_DEFUN([WZD_LIB_TCL],
[
  dnl  Process the 'with-tcl' switch. We set the variable 'places' to
  dnl  either 'search', meaning we should check in a list of typical places,
  dnl  or to a single place spec.
  dnl
  dnl  A 'place spec' is either:
  dnl    - the string 'std', indicating that we should look doe headers and
  dnl      librairies in the standard places,
  dnl    - a directory prefix P, indicating we should look for headers in
  dnl      P/include and librairies in P/lib, or
  dnl    - a string of the form 'HEADER:LIB', indicating that we should look
  dnl      for headers in HEADER and libraries in LIB.
  dnl
  dnl  You'll notice that the value of the '--with-tcl' switch is a
  dnl  place spec.

  AC_ARG_WITH(tcl,
    AC_HELP_STRING(--with-tcl=PATH, [alternate location of TCL headers and libs]),
  [
    if test "$withval" = "yes"; then
      places=search
    else
      places="$withval"
    fi
  ],
  [
    places=search
  ])

  if test "$places" = "search"; then
    places="std /usr/include/tcl:/usr/lib /usr/include/tcl8.4:/usr/lib/tcl8.4
            /usr/include/tcl8.3:/usr/lib/tcl8.3
            /usr/local/include/tcl:/usr/local/lib"
  fi
  # now 'places' is guaranteed to be a list of place specs we should
  # search, no matter what flags the user passed

  # Save the original values of the flags we tweak
  WZD_LIB_TCL_save_libs="$LIBS"
  WZD_LIB_TCL_save_cppflags="$CPPFLAGS"

  # The variable 'found' is the prefix under which we've found
  # TCL, or 'not' if we haven't found it anywhere yet.
  found=not
  for place in $places; do

    LIBS="$WZD_LIB_TCL_save_libs"
    CPPFLAGS="$WZD_LIB_TCL_save_cppflags"
    case "$place" in
      "std" )
        description="the standard places"
      ;;
      *":"* )
        header="`echo $place | sed -e 's/:.*$//'`"
        lib="`echo $place | sed -e 's/^.*://'`"
        CPPFLAGS="$CPPFLAGS -I$header"
        LIBS="$LIBS -L$lib"
        description="$place"
      ;;
      * )
        LIBS="$LIBS -L$place/lib"
        CPPFLAGS="$CPPFLAGS -I$place/include"
        description="$place"
      ;;
    esac

    # We generate a separate cache variable for each prefix
    # we search under. That way, we avoid caching information that
    # changes if the user runs 'configure' with a different set of
    # switches.
    changequote(,)
    cache_id="`echo wzd_cv_lib_tcl_$1_$2_$3_in_${place} \
                 | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
    changequote([,])
    dnl We can't use AC_CACHE_CHECK here, because that won(t print out
    dnl the value of the computed cache variable properly.
    AC_MSG_CHECKING([for TCL in $description])
    AC_CACHE_VAL($cache_id,
      [
        WZD_LIB_TCL_TRY($1, $2, $3)
          eval "$cache_id=$wzd_have_tcl"
      ])
    result="`eval echo '$'$cache_id`"
    AC_MSG_RESULT($result)

    # If we found it, no need to search any more
    if test "`eval echo '$'$cache_id`" = "yes"; then
      found="$place"
      break
    fi
  done

  # Restore the original values of the flags we tweak
  LIBS="$WZD_LIB_TCL_save_libs"
  CPPFLAGS="$WZD_LIB_TCL_save_cppflags"

  case "$found" in
    "not" )
      dnl AC_MSG_ERROR([Could not find TCL $tcl_version (or higher)])
      WZD_TCL_INCLUDES=
      WZD_TCL_LIBS=
      wzd_lib_tcl=no
      m4_ifval([$2])
    ;;
    "std" )
      WZD_TCL_INCLUDES=
      WZD_TCL_LIBS="-ltcl8.4"
      wzd_lib_tcl=yes
      AC_DEFINE(HAVE_TCL, 1, [Define if using tcl])
      m4_ifval([$1])
    ;;
    *":"* )
      header="`echo $found | sed -e 's/:.*$//'`"
      lib="`echo $found | sed -e 's/^.*://'`"
      WZD_TCL_INCLUDES="-I$header"
      WZD_TCL_LIBS="-L$lib -ltcl8.4"
      wzd_lib_tcl=yes
      AC_DEFINE(HAVE_TCL, 1, [Define if using tcl])
      m4_ifval([$1])
    ;;
    * )
      WZD_TCL_INCLUDES="-I$found/include"
      WZD_TCL_LIBS="-L$found/lib -ltcl8.4"
      wzd_lib_tcl=yes
      AC_DEFINE(HAVE_TCL, 1, [Define if using tcl])
      m4_ifval([$1])
    ;;
  esac
  AC_SUBST(WZD_TCL_INCLUDES)
  AC_SUBST(WZD_TCL_LIBS)
])

dnl    WZD_LIB_TCL_TRY()
dnl
dnl    A subroutine of WZD_LIB_TCL.
dnl
dnl    Check that a new-enough version of TCL is installed.
dnl
dnl    Set the shell variable 'wzd_have_tcl' to 'yes' if we found
dnl    an appropriate version installed, or 'no' otherwise.

AC_DEFUN([WZD_LIB_TCL_TRY],
  [
    wzd_lib_tcl_try_save_libs="$LIBS"

    LIBS="$LIBS -ltcl8.4"

    dnl not trying to run, there's no point
    AC_TRY_LINK([#include "tcl.h"],[Tcl_Interp * interp; Tcl_Init(interp);],[wzd_have_tcl=yes],[wzd_have_tcl=no])

    LIBS="$wzd_lib_tcl_try_save_libs"
  ]
)
