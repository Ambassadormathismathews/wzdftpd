AUTOMAKE_OPTIONS = 1.5	# Require Automake 1.5 or better.

if HAVE_MYSQL
  MAYBE_MYSQL = mysql
endif

if HAVE_SQLITE3
  MAYBE_SQLITE3 = sqlite
endif

if HAVE_PAM
  MAYBE_PAM = pam
endif

if HAVE_PGSQL
  MAYBE_PGSQL = pgsql
endif

SUBDIRS = plaintext $(MAYBE_MYSQL) $(MAYBE_SQLITE3) $(MAYBE_PAM) $(MAYBE_PGSQL)
