dnl   WZD_LIB_MYSQL()
dnl
dnl   Search for a useable version of the MySQL client libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `wzd_lib_mysql' to
dnl   `yes'.  Otherwise, set `wzd_lib_mysql' to `no'.
dnl


AC_DEFUN([WZD_LIB_MYSQL],
[
  AC_REQUIRE([AC_CANONICAL_TARGET])
  AC_PATH_PROG(MYSQL_CONFIG, mysql_config, no)
  AC_MSG_CHECKING(for MySQL)

  no_mysql=""
  if test "$MYSQL_CONFIG" = "no" ; then
    WZD_MYSQL_INCLUDES=
    WZD_MYSQL_LIBS=""
    AC_MSG_RESULT(no)
    wzd_have_mysql=no
    ifelse([$2], , :, [$2])
  else
    WZD_MYSQL_INCLUDES=`$MYSQL_CONFIG $mysqlconf_args --cflags | sed -e "s/'//g"`
    WZD_MYSQL_LIBS=`$MYSQL_CONFIG $mysqlconf_args --libs | sed -e "s/'//g"`
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_MYSQL, 1, [Define if using mysql])
    wzd_have_mysql=yes
    ifelse([$1], , :, [$1])
  fi
  AC_SUBST(WZD_MYSQL_INCLUDES)
  AC_SUBST(WZD_MYSQL_LIBS)
])

