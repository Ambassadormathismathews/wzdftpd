dnl The Pgsql part is adapted from the jabberd2 cvs
dnl (available at http://www.jabberstudio.org)
dnl and was slightly modified to fit wzdftpd.

dnl   WZD_LIB_PGSQL()
dnl  
dnl   Search for a useable version of the PostgreSQL client libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set WZD_PGSQL_INCLUDES and WZD_PGSQL_LIBS as
dnl   appropriate, and set the shell variable 'wzd_have_pgsql' to
dnl   'yes'. Otherwise, set 'wzd_have_pgsql' to 'no'.
dnl   
dnl   The macro will execute optional argument 1 if given, if PostgreSQL
dnl   client libs are found.
dnl   
dnl   This macro alse checks for the '--with-pgsql=PATH' flags;
dnl   if given, the macro will use the PATH specified, and the
dnl   configuration script will execute macro arg 2 if given.
dnl   
dnl   We cache the results of individual searches under particular
dnl   prefixes, not the overall result of whether we found PostgreSQL.
dnl   That way, the user can re-run the configure script with
dnl   different --with-pgsql switch values, without interference
dnl   from the cache.

AC_DEFUN([WZD_LIB_PGSQL],
[
  dnl  Process the 'with-psql' switch. We set the variable 'places' to
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
  dnl  You'll notice that the value of the '--with-pgsql' switch is a
  dnl  place spec.

  AC_ARG_WITH(pgsql,
    AC_HELP_STRING(--with-pgsql=PATH, [alternate location of PostgreSQL headers and libs]),
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
    places="std /usr/include/postgresql:/usr/lib /usr/local/sw/include/postgresql:/sw/lib
            /usr/local/include/postgresql:/usr/local/lib"
  fi
  # now 'places' is guaranteed to be a list of place specs we should
  # search, no matter what flags the user passed

  # Save the original values of the flags we tweak
  WZD_LIB_PGSQL_save_libs="$LIBS"
  WZD_LIB_PGSQL_save_cppflags="$CPPFLAGS"

  # The variable 'found' is the prefix under which we've found
  # PostgreSQL, or 'not' if we haven't found it anywhere yet.
  found=not
  for place in $places; do

    LIBS="$WZD_LIB_PGSQL_save_libs"
    CPPFLAGS="$WZD_LIB_PGSQL_save_cppflags"
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
    cache_id="`echo wzd_cv_lib_pgsql_$1_$2_$3_in_${place} \
                 | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
    changequote([,])
    dnl We can't use AC_CACHE_CHECK here, because that won(t print out
    dnl the value of the computed cache variable properly.
    AC_MSG_CHECKING([for PostgreSQL in $description])
    AC_CACHE_VAL($cache_id,
      [
        WZD_LIB_PGSQL_TRY($1, $2, $3)
          eval "$cache_id=$wzd_have_pgsql"
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
  LIBS="$WZD_LIB_PGSQL_save_libs"
  CPPFLAGS="$WZD_LIB_PGSQL_save_cppflags"

  case "$found" in
    "not" )
      dnl AC_MSG_ERROR([Could not find PostgreSQL $pgsql_version (or higher)])
      WZD_PGSQL_INCLUDES=
      WZD_PGSQL_LIBS=
      wzd_lib_pgsql=no
      m4_ifval([$2])
    ;;
    "std" )
      WZD_PGSQL_INCLUDES=
      WZD_PGSQL_LIBS="-lpq"
      wzd_lib_pgsql=yes
      AC_DEFINE(HAVE_PGSQL, 1, [Define if using pgsql])
      m4_ifval([$1])
    ;;
    *":"* )
      header="`echo $found | sed -e 's/:.*$//'`"
      lib="`echo $found | sed -e 's/^.*://'`"
      WZD_PGSQL_INCLUDES="-I$header"
      WZD_PGSQL_LIBS="-L$lib -lpq"
      wzd_lib_pgsql=yes
      AC_DEFINE(HAVE_PGSQL, 1, [Define if using pgsql])
      m4_ifval([$1])
    ;;
    * )
      WZD_PGSQL_INCLUDES="-I$found/include"
      WZD_PGSQL_LIBS="-L$found/lib -lpq"
      wzd_lib_pgsql=yes
      AC_DEFINE(HAVE_PGSQL, 1, [Define if using pgsql])
      m4_ifval([$1])
    ;;
  esac
  AC_SUBST(WZD_PGSQL_INCLUDES)
  AC_SUBST(WZD_PGSQL_LIBS)
])

dnl    WZD_LIB_PGSQL_TRY()
dnl
dnl    A subroutine of WZD_LIB_PGSQL.
dnl
dnl    Check that a new-enough version of PostgreSQL is installed.
dnl
dnl    Set the shell variable 'wzd_have_pgsql' to 'yes' if we found
dnl    an appropriate version installed, or 'no' otherwise.

AC_DEFUN([WZD_LIB_PGSQL_TRY],
  [
    wzd_lib_pgsql_try_save_libs="$LIBS"

    LIBS="$LIBS -lpq"

    dnl not trying to run, there's no point
    AC_TRY_LINK([#include "libpq-fe.h"],[PQsetdbLogin(0,0,0,0,0,0,0);],[wzd_have_pgsql=yes],[wzd_have_pgsql=no])

    LIBS="$wzd_lib_pgsql_try_save_libs"
  ]
)
