dnl The Mysql part is adapted from the jabberd2 cvs
dnl (available at http://www.jabberstudio.org)
dnl and was slightly modified to fit wzdftpd.

dnl   WZD_LIB_MYSQL()
dnl
dnl   Search for a useable version of the MySQL client libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `wzd_lib_mysql' to
dnl   `yes'.  Otherwise, set `wzd_lib_mysql' to `no'.
dnl
dnl   This macro also checks for the `--with-mysql=PATH' flag;
dnl   if given, the macro will use the PATH specified, and the
dnl   configuration script will die if it can't find the library.
dnl
dnl   We cache the results of individual searches under particular
dnl   prefixes, not the overall result of whether we found MySQL
dnl   That way, the user can re-run the configure script with
dnl   different --with-mysql switch values, without interference
dnl   from the cache.


AC_DEFUN(WZD_LIB_MYSQL,
[
  dnl  Process the `with-mysql' switch. We set the variable `places' to
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
  dnl  You'll notice that the value of the `--with-mysql' switch is a
  dnl  place spec.

  AC_ARG_WITH(mysql,
    AC_HELP_STRING(--with-mysql=PATH, [alternate location of MySQL headers and libs]),
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
    places="std /usr/include/mysql:/usr/lib /usr/local
            /usr/include/mysql:/usr/lib/mysql
            /usr/local/include/mysql:/usr/local/lib/mysql
            /usr/local/include/mysql:/usr/local/lib
            /sw/include/mysql:/sw/lib"
  fi
  # Now `places' is guaranteed to be a list of place specs we should
  # search, no matter what flags the user passed.

  # Save the original values of the flags we tweak.
  WZD_LIB_MYSQL_save_libs="$LIBS"
  WZD_LIB_MYSQL_save_cppflags="$CPPFLAGS"

  # The variable `found' is the prefix under which we've found
  # MySQL, or `not' if we haven't found it anywhere yet.
  found=not
  for place in $places; do

    LIBS="$WZD_LIB_MYSQL_save_libs"
    CPPFLAGS="$WZD_LIB_MYSQL_save_cppflags"
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

    # We generate a separate cache variable for each prefix
    # we search under.  That way, we avoid caching information that
    # changes if the user runs `configure' with a different set of
    # switches.
    changequote(,)
    cache_id="`echo wzd_cv_lib_mysql_$1_$2_$3_in_${place} \
                 | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
    changequote([,])
    dnl We can't use AC_CACHE_CHECK here, because that won't print out
    dnl the value of the computed cache variable properly.
    AC_MSG_CHECKING([for MySQL in $description])
    AC_CACHE_VAL($cache_id,
      [
       WZD_LIB_MYSQL_TRY()
         eval "$cache_id=$wzd_have_mysql"
      ])
    result="`eval echo '$'$cache_id`"
    AC_MSG_RESULT($result)

    # If we found it, no need to search any more.
    if test "`eval echo '$'$cache_id`" = "yes"; then
      found="$place"
      break
    fi

    test "$found" != "not" && break
  done

  # Restore the original values of the flags we tweak.
  LIBS="$WZD_LIB_MYSQL_save_libs"
  CPPFLAGS="$WZD_LIB_MYSQL_save_cppflags"

  case "$found" in
    "not" )
      dnl AC_MSG_ERROR([Could not find MySQL])
      WZD_MYSQL_INCLUDES=
      WZD_MYSQL_LIBS=""
      wzd_lib_mysql=no
      m4_ifval([$2])
    ;;
    "std" )
      WZD_MYSQL_INCLUDES=
      WZD_MYSQL_LIBS="-lmysqlclient"
      wzd_lib_mysql=yes
      AC_DEFINE(HAVE_MYSQL, 1, [Define if using mysql])
      m4_ifval([$1])
    ;;
    *":"* )
      header="`echo $found | sed -e 's/:.*$//'`"
      lib="`echo $found | sed -e 's/^.*://'`"
      WZD_MYSQL_INCLUDES="-I$header"
      WZD_MYSQL_LIBS="-L$lib -lmysqlclient"
      wzd_lib_mysql=yes
      AC_DEFINE(HAVE_MYSQL, 1, [Define if using mysql])
      m4_ifval([$1])
    ;;
    * )
      WZD_MYSQL_INCLUDES="-I$found/include"
      WZD_MYSQL_LIBS="-L$found/lib -lmysqlclient"
      wzd_lib_mysql=yes
      AC_DEFINE(HAVE_MYSQL, 1, [Define if using mysql])
      m4_ifval([$1])
    ;;
  esac
  AC_SUBST(WZD_MYSQL_INCLUDES)
  AC_SUBST(WZD_MYSQL_LIBS)
])


dnl   WZD_LIB_MYSQL_TRY()
dnl
dnl   A subroutine of WZD_LIB_MYSQL.
dnl
dnl   Check that a new-enough version of MySQL is installed.
dnl
dnl   Set the shell variable `wzd_have_mysql' to `yes' if we found
dnl   an appropriate version installed, or `no' otherwise.


AC_DEFUN(WZD_LIB_MYSQL_TRY,
  [
    wzd_lib_mysql_try_save_libs="$LIBS"

    LIBS="$LIBS -lmysqlclient"

    dnl not trying to run, there's no point
    AC_TRY_LINK([#include "mysql.h"],[mysql_init(0);],[wzd_have_mysql=yes],[wzd_have_mysql=no])

    LIBS="$wzd_lib_mysql_try_save_libs"
  ]
)
