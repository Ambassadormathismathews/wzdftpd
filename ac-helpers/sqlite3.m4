dnl   WZD_LIB_SQLITE3()
dnl
dnl   Search for a useable version of the Sqlite3 libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `wzd_lib_sqlite3' to
dnl   `yes'.  Otherwise, set `wzd_lib_sqlite3' to `no'.
dnl


AC_DEFUN([WZD_LIB_SQLITE3],
[
  AC_ARG_ENABLE(sqlite3, [  --disable-sqlite3        disable sqlite3 support])

  if eval "test x$enable_sqlite3 = xno"; then
    WZD_SQLITE3_INCLUDES=""
    WZD_SQLITE3_LIBS=""
    wzd_have_sqlite3=no
    ifelse([$2], , :, [$2])
  else
    PKG_CHECK_MODULES(WZD_SQLITE3, sqlite3, wzd_have_sqlite3=yes, wzd_have_sqlite3=no)
  fi
  WZD_SQLITE3_INCLUDES=$WZD_SQLITE3_CFLAGS
  AC_SUBST(WZD_SQLITE3_INCLUDES)
  AC_SUBST(WZD_SQLITE3_LIBS)
])

