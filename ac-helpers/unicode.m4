dnl   WZD_LIB_UNICODE()
dnl  
dnl   Search for unicode functions

AC_DEFUN([WZD_LIB_UNICODE],
[
  AC_CHECK_HEADERS(wchar.h)

  AC_CACHE_CHECK([for wchar_t], wzd_cv_wchar_t,
    AC_TRY_COMPILE([
#include <stddef.h>
#include <stdlib.h>
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
    ],
    [ wchar_t wc; return 0; ],
    wzd_cv_wchar_t=yes,
    wzd_cv_wchar_t=no))

  if test "$wzd_cv_wchar_t" = no; then
    AC_DEFINE(wchar_t,int,[ Define to 'int' if system headers don't define. ])
  fi

  AC_CACHE_CHECK([for wint_t], wzd_cv_wint_t,
    AC_TRY_COMPILE([
#include <stddef.h>
#include <stdlib.h>
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
    ],
    [ wint_t wc; return 0; ],
    wzd_cv_wint_t=yes,
    wzd_cv_wint_t=no))

  if test "$wzd_cv_wint_t" = no; then
    AC_DEFINE(wint_t,int,[ Define to 'int' if system headers don't define. ])
  fi

  AC_CHECK_HEADERS(wctype.h)
  AC_CHECK_FUNCS(iswalnum iswalpha iswcntrl iswdigit)
  AC_CHECK_FUNCS(iswgraph iswlower iswprint iswpunct iswspace iswupper)
  AC_CHECK_FUNCS(iswxdigit towupper towlower)

  AC_CACHE_CHECK([for mbstate_t], wzd_cv_mbstate_t,
    AC_TRY_COMPILE([
#include <stddef.h>
#include <stdlib.h>
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
    ],
    [ mbstate_t s; return 0; ],
    wzd_cv_mbstate_t=yes,
    wzd_cv_mbstate_t=no))

  if test "$wzd_cv_mbstate_t" = no; then
    AC_DEFINE(mbstate_t,int,[ Define to 'int' if system headers don't define. ])
  fi

  wc_funcs=maybe
  AC_ARG_WITH(wc-funcs, [  --without-wc-funcs      Do not use the system's wchar_t functions],
    wc_funcs=$withval)

  if test "$wc_funcs" != yes -a "$wc_funcs" != no; then
    AC_CACHE_CHECK([for wchar_t functions], wzd_cv_wc_funcs,
      wzd_cv_wc_funcs=no
      AC_TRY_LINK([
#define _XOPEN_SOURCE 1
#include <stddef.h>
#include <stdlib.h>
#ifdef HAVE_WCTYPE_H
#include <wctype.h>
#endif
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif],
	[mbrtowc(0, 0, 0, 0); wctomb( 0, 0); wcwidth(0);
          iswprint(0); iswspace(0); towlower(0); towupper(0); iswalnum(0);],
        wzd_cv_wc_funcs=yes))
    wc_funcs=$wzd_cv_wc_funcs
  fi

  if test $wc_funcs = yes; then
    AC_DEFINE(HAVE_WC_FUNCS,1,[ Define if you are using the system's wchar_t functions. ])
  fi

  WZD_LANGINFO_CODESET

dnl  AC_SUBST(WZD_PGSQL_LIBS)
])

AC_DEFUN([WZD_LANGINFO_CODESET],
[
  AC_CHECK_HEADERS(langinfo.h)
  AC_CHECK_FUNCS(nl_langinfo)

  AC_CACHE_CHECK([for nl_langinfo and CODESET], wzd_cv_langinfo_codeset,
    [AC_TRY_LINK([#include <langinfo.h>],
      [char* cs = nl_langinfo(CODESET);],
      wzd_cv_langinfo_codeset=yes,
      wzd_cv_langinfo_codeset=no)
    ])
  if test $wzd_cv_langinfo_codeset = yes; then
    AC_DEFINE(HAVE_LANGINFO_CODESET, 1,
      [Define if you have <langinfo.h> and nl_langinfo(CODESET).])
  fi
])
