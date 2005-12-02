dnl   WZD_LIB_KRB5()
dnl
dnl   Search for a useable version of the Kerberos client libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `wzd_lib_krb5' to
dnl   `yes'.  Otherwise, set `wzd_lib_krb5' to `no'.
dnl


AC_DEFUN([WZD_LIB_KRB5],
[

  AC_MSG_CHECKING(whether to enable kerberos support)

  wzd_have_kerberos=no
  AC_ARG_ENABLE(kerberos, [  --enable-kerberos       enable kerberos support (EXPERIMENTAL)],
      if eval "test x$enable_kerberos = xyes"; then
        AC_MSG_RESULT(yes)
      else
        AC_MSG_RESULT(no)
      fi,
      AC_MSG_RESULT(no)
  )

  if eval "test x$enable_kerberos = xyes"; then
    AC_REQUIRE([AC_CANONICAL_TARGET])
    AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
    AC_MSG_CHECKING(for Kerberos)
  
    no_krb5=""
    if test "$KRB5_CONFIG" = "no" ; then
      WZD_KRB5_INCLUDES=
      WZD_KRB5_LIBS=""
      AC_MSG_RESULT(no)
      wzd_have_krb5=no
      ifelse([$2], , :, [$2])
    else
      WZD_KRB5_INCLUDES=`$KRB5_CONFIG $krb5conf_args --cflags gssapi | sed -e "s/'//g"`
      WZD_KRB5_LIBS=`$KRB5_CONFIG $krb5conf_args --libs gssapi | sed -e "s/'//g"`
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_KRB5, 1, [Define if using krb5])
      wzd_have_krb5=yes
      ifelse([$1], , :, [$1])
    fi
    AC_SUBST(WZD_KRB5_INCLUDES)
    AC_SUBST(WZD_KRB5_LIBS)
  fi
])

