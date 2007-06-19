SUBDIRS(plaintext)

IF(MYSQL_FOUND)
  add_subdirectory(mysql)
ENDIF(MYSQL_FOUND)

IF(PAM_FOUND)
  add_subdirectory(pam)
ENDIF(PAM_FOUND)

IF(POSTGRESQL_FOUND)
  add_subdirectory(pgsql)
ENDIF(POSTGRESQL_FOUND)

IF(SQLITE3_FOUND)
  add_subdirectory(sqlite)
ENDIF(SQLITE3_FOUND)

