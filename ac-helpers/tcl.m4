dnl   WZD_LIB_TCL()
dnl  
dnl   Search for a useable version of the TCL libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set WZD_TCL_INCLUDES and WZD_TCL_LIBS as
dnl   appropriate, and set the shell variable 'wzd_have_tcl' to
dnl   'yes'. Otherwise, set 'wzd_have_tcl' to 'no'.
dnl   


AC_DEFUN([WZD_LIB_TCL],
[
  AC_ARG_WITH(tcl,
    AC_HELP_STRING(--with-tcl=PATH, [alternate location of TCL script tclConfig.sh]),
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
    places="/usr/lib
            /usr/lib/tcl8.4
            /usr/local/lib/tcl8.4
            /usr/lib/tcl8.3
            /usr/local/lib"
  fi

  # now 'places' is guaranteed to be a list of place specs we should
  # search, no matter what flags the user passed

  AC_MSG_CHECKING([for TCL ])

  # The variable 'found' is the prefix under which we've found
  # TCL, or 'not' if we haven't found it anywhere yet.
  found=not
  for place in $places; do
    if test -f "$place/tclConfig.sh" ; then
      wzd_cv_path_tcl_config="$place"
      found="$place"
      AC_MSG_RESULT($place/tclConfig.h)
      break;
    fi
  done

  # test the location !
  if test "$found" != "not"; then

    . $place/tclConfig.sh

    WZD_TCL_LIBS=$(eval echo $TCL_LIB_SPEC)
    WZD_TCL_INCLUDES=$(eval echo $TCL_INCLUDE_SPEC)

    AC_MSG_CHECKING([if tclConfig.sh is useable])

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
    AC_CACHE_VAL($cache_id,
      [
        WZD_LIB_TCL_TRY($WZD_TCL_INCLUDES, $WZD_TCL_LIBS)
          eval "$cache_id=$wzd_have_tcl"
      ])
    result="`eval echo '$'$cache_id`"
    AC_MSG_RESULT($result)

    # Restore the original values of the flags we tweak
    LIBS="$WZD_LIB_TCL_save_libs"
    CPPFLAGS="$WZD_LIB_TCL_save_cppflags"
  fi

  case "$found" in
    "not" )
      dnl AC_MSG_ERROR([Could not find TCL $tcl_version (or higher)])
      AC_MSG_RESULT(not found)
      WZD_TCL_INCLUDES=
      WZD_TCL_LIBS=
      wzd_lib_tcl=no
      m4_ifval([$2])
    ;;
    * )
      AC_MSG_CHECKING(for tcl version)
      AC_MSG_RESULT("$TCL_VERSION")
      if test x"$1" != "x"; then
	if test $1 -gt $TCL_MAJOR_VERSION; then
	  AC_MSG_ERROR("tcl $1 or later needed")
	fi
	if test x"$2" != "x"; then
	  if test $2 -gt $TCL_MINOR_VERSION; then
	    AC_MSG_ERROR("tcl $1.$2 or later needed")
	  fi
	fi
      fi
      WZD_TCL_LIBS=$(eval echo $TCL_LIB_SPEC)
      WZD_TCL_INCLUDES=$(eval echo $TCL_INCLUDE_SPEC)
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
    wzd_lib_tcl_try_save_cflags="$CFLAGS"
    wzd_lib_tcl_try_save_libs="$LIBS"

    CFLAGS="$CFLAGS $1"
    LIBS="$LIBS $2"

    dnl not trying to run, there's no point
    AC_TRY_LINK([#include "tcl.h"],[Tcl_Interp * interp; Tcl_Init(interp);],[wzd_have_tcl=yes],[wzd_have_tcl=no])

    CFLAGS="$wzd_lib_tcl_try_save_cflags"
    LIBS="$wzd_lib_tcl_try_save_libs"
  ]
)
