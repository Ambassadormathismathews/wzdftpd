AUTOMAKE_OPTIONS = 1.5	# Require Automake 1.5 or better.

if HAVE_MYSQL
  MAYBE_MYSQL = mysql
endif

if HAVE_PAM
  MAYBE_PAM = pam
endif

SUBDIRS = plaintext $(MAYBE_MYSQL) $(MAYBE_PAM)
