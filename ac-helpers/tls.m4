dnl   WZD_TLS()
dnl
dnl   Search for a useable TLS implementation, either GnuTLS or OpenSSL
dnl   GnuTLS is preferred if found.
dnl
dnl   Each test can be removed using --disable-gnutls or --disable-openssl
dnl

AC_DEFUN([WZD_TLS],
[
  gnutls=yes
  AC_ARG_ENABLE(gnutls, AC_HELP_STRING([ --disable-gnutls ], [ disable gnutls/gcrypt ]),
  if test "x$enable_gnutls" != "xyes"; then
    gnutls="disabled"
  fi
  )
  openssl=yes
  AC_ARG_ENABLE(openssl, AC_HELP_STRING([ --disable-openssl ], [ disable openssl ]),
  if test "x$enable_openssl" != "xyes"; then
    openssl="disabled"
  fi
  )

if test "$gnutls" = "yes"; then
AM_PATH_LIBGNUTLS(0.9.8,wzd_have_gnutls=yes)
fi

# openssl is checked only if gnutls was not found or disabled
if test "x$wzd_have_gnutls" = "xyes"; then
  AC_DEFINE(HAVE_GNUTLS,1,"Define to 1 if you have the gnutls library")
  CFLAGS="$CFLAGS $LIBGNUTLS_CFLAGS"
  LDFLAGS="$LDFLAGS $LIBGNUTLS_LIBS"
else
  if test "$openssl" = "yes"; then
    WZD_LIB_OPENSSL(0,9,6,2)
  fi
fi

])

