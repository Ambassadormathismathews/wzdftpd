dnl The Berkeley DB part is adapted from the jabberd2 cvs
dnl (available at http://www.jabberstudio.org)
dnl and was slightly modified to fit wzdftpd.

dnl This was heavily modified from berkeley-db.m4 included with
dnl Subversion (r5118). Originally copyright (c) 2002-2003 CollabNet.

dnl   WZD_LIB_BERKELEY_DB(major, minor, patch, libname)
dnl
dnl   Search for a useable version of Berkeley DB in a number of
dnl   common places.  The installed DB must be no older than the
dnl   version given by MAJOR, MINOR, and PATCH.  LIBNAME is a list of
dnl   names of the library to attempt to link against, typically
dnl   'db' and 'db4'.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `wzd_lib_berkeley_db' to
dnl   `yes'.  Otherwise, set `wzd_lib_berkeley_db' to `no'.
dnl
dnl   This macro also checks for the `--with-berkeley-db=PATH' flag;
dnl   if given, the macro will use the PATH specified, and the
dnl   configuration script will die if it can't find the library.  If
dnl   the user gives the `--without-berkeley-db' flag, the entire
dnl   search is skipped.
dnl
dnl   We cache the results of individual searches under particular
dnl   prefixes, not the overall result of whether we found Berkeley
dnl   DB.  That way, the user can re-run the configure script with
dnl   different --with-berkeley-db switch values, without interference
dnl   from the cache.


AC_DEFUN([WZD_LIB_BERKELEY_DB],
[
  db_version=$1.$2.$3
  dnl  Process the `with-berkeley-db' switch. We set the variable `places' to
  dnl  either `search', meaning we should check in a list of typical places,
  dnl  or to a single place spec.
  dnl
  dnl  A `place spec' is either:
  dnl    - the string `std', indicating that we should look for headers and
  dnl      libraries in the standard places,
  dnl    - a directory prefix P, indicating we should look for headers in
  dnl      P/include and libraries in P/lib, or
  dnl    - a string of the form `HEADER:LIB', indicating that we should look
  dnl      for headers in HEADER and libraries in LIB.
  dnl 
  dnl  You'll notice that the value of the `--with-berkeley-db' switch is a
  dnl  place spec.

  AC_ARG_WITH(berkeley-db,
    AC_HELP_STRING(--with-berkeley-db=PATH, [alternate location of Berkeley DB headers and libs]),
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
      places="std /usr/local/include/db4:/usr/local/lib /usr/local
              /usr/local/BerkeleyDB.$1.$2 /usr/include/db4:/usr/lib
              /sw/include/db4:/sw/lib"
    fi
    # Now `places' is guaranteed to be a list of place specs we should
    # search, no matter what flags the user passed.

    # Save the original values of the flags we tweak.
    WZD_LIB_BERKELEY_DB_save_libs="$LIBS"
    WZD_LIB_BERKELEY_DB_save_cppflags="$CPPFLAGS"

    AC_MSG_CHECKING([for Berkeley DB])

    # The variable `found' is the prefix under which we've found
    # Berkeley DB, or `not' if we haven't found it anywhere yet.
    found=not
    for place in $places; do

      LIBS="$WZD_LIB_BERKELEY_DB_save_libs"
      CPPFLAGS="$WZD_LIB_BERKELEY_DB_save_cppflags"
      case "$place" in
        "std" )
          description="the standard places"
        ;;
        *":"* )
          header="`echo $place | sed -e 's/:.*$//'`"
          lib="`echo $place | sed -e 's/^.*://'`"
	  CPPFLAGS="$CPPFLAGS -I$header"
	  LIBS="$LIBS -L$lib"
	  description="$header and $lib"
        ;;
        * )
	  LIBS="$LIBS -L$place/lib"
	  CPPFLAGS="$CPPFLAGS -I$place/include"
	  description="$place"
        ;;
      esac

      for db_libname in $4; do
        # We generate a separate cache variable for each prefix and libname
        # we search under.  That way, we avoid caching information that
        # changes if the user runs `configure' with a different set of
        # switches.
        changequote(,)
        cache_id="`echo wzd_cv_lib_berkeley_db_$1_$2_$3_${db_libname}_in_${place} \
                   | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
        changequote([,])
        dnl We can't use AC_CACHE_CHECK here, because that won't print out
        dnl the value of the computed cache variable properly.
        dnl AC_MSG_CHECKING([for Berkeley DB in $description (as $db_libname)])
        AC_CACHE_VAL($cache_id,
          [
  	  WZD_LIB_BERKELEY_DB_TRY($1, $2, $3, $db_libname)
            eval "$cache_id=$wzd_have_berkeley_db"
          ])
        result="`eval echo '$'$cache_id`"
        dnl AC_MSG_RESULT($result)

        # If we found it, no need to search any more.
        if test "`eval echo '$'$cache_id`" = "yes"; then
          found="$place"
          break
        fi
      done
        test "$found" != "not" && break
    done

    # Restore the original values of the flags we tweak.
    LIBS="$WZD_LIB_BERKELEY_DB_save_libs"
    CPPFLAGS="$WZD_LIB_BERKELEY_DB_save_cppflags"

    case "$found" in
      "not" )
	dnl AC_MSG_ERROR([Could not find Berkeley DB $db_version (or higher) with names: $4])
	wzd_lib_berkeley_db=no
	AC_MSG_RESULT(not found)
      ;;
      "std" )
        WZD_DB_INCLUDES=
        WZD_DB_LIBS=-l$db_libname
        wzd_lib_berkeley_db=yes
	AC_MSG_RESULT(found)
	AC_DEFINE(HAVE_DB, 1, [Define if using berkeley db])
      ;;
      *":"* )
	header="`echo $found | sed -e 's/:.*$//'`"
	lib="`echo $found | sed -e 's/^.*://'`"
        WZD_DB_INCLUDES="-I$header"
dnl ### should look for a .la file
        WZD_DB_LIBS="-L$lib -l$db_libname"
	AC_MSG_RESULT(found)
	AC_DEFINE(HAVE_DB, 1, [Define if using berkeley db])
        wzd_lib_berkeley_db=yes
      ;;
      * )
        WZD_DB_INCLUDES="-I$found/include"
dnl ### should look for a .la file
        WZD_DB_LIBS="-L$found/lib -l$db_libname"
	AC_MSG_RESULT(found)
	AC_DEFINE(HAVE_DB, 1, [Define if using berkeley db])
	wzd_lib_berkeley_db=yes
      ;;
    esac
  AC_SUBST(WZD_DB_INCLUDES)
  AC_SUBST(WZD_DB_LIBS)
])


dnl   WZD_LIB_BERKELEY_DB_TRY(major, minor, patch, db_name)
dnl
dnl   A subroutine of WZD_LIB_BERKELEY_DB.
dnl
dnl   Check that a new-enough version of Berkeley DB is installed.
dnl   "New enough" means no older than the version given by MAJOR,
dnl   MINOR, and PATCH.  The result of the test is not cached; no
dnl   messages are printed.  Use DB_NAME as the library to link against.
dnl   (e.g. DB_NAME should usually be "db" or "db4".)
dnl
dnl   Set the shell variable `wzd_have_berkeley_db' to `yes' if we found
dnl   an appropriate version installed, or `no' otherwise.
dnl
dnl   This macro uses the Berkeley DB library function `db_version' to
dnl   find the version.  If the library installed doesn't have this
dnl   function, then this macro assumes it is too old.


AC_DEFUN([WZD_LIB_BERKELEY_DB_TRY],
  [
    wzd_lib_berkeley_db_try_save_libs="$LIBS"

    wzd_check_berkeley_db_major=$1
    wzd_check_berkeley_db_minor=$2
    wzd_check_berkeley_db_patch=$3
    wzd_berkeley_db_lib_name=$4

    LIBS="$LIBS -l$wzd_berkeley_db_lib_name"

    AC_TRY_RUN(
      [
#include "db.h"
#include <stdio.h>
main ()
{
  int major, minor, patch;

  db_version (&major, &minor, &patch);

  /* Sanity check: ensure that db.h constants actually match the db library */
  if (major != DB_VERSION_MAJOR
      || minor != DB_VERSION_MINOR
      || patch != DB_VERSION_PATCH)
    exit (1);

  /* Run-time check:  ensure the library claims to be the correct version. */

  if (major < $wzd_check_berkeley_db_major)
    exit (1);
  if (major > $wzd_check_berkeley_db_major)
    exit (0);

  if (minor < $wzd_check_berkeley_db_minor)
    exit (1);
  if (minor > $wzd_check_berkeley_db_minor)
    exit (0);

  if (patch >= $wzd_check_berkeley_db_patch)
    exit (0);
  else
    exit (1);
}
      ],
      [wzd_have_berkeley_db=yes],
      [wzd_have_berkeley_db=no],
      [wzd_have_berkeley_db=yes]
    )

  LIBS="$wzd_lib_berkeley_db_try_save_libs"
  ]
)
