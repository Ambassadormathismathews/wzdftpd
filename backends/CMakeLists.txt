SUBDIRS(plaintext)

IF(MYSQL_FOUND)
  add_subdirectory(mysql)
ENDIF(MYSQL_FOUND)

IF(POSTGRESQL_FOUND)
  add_subdirectory(pgsql)
ENDIF(POSTGRESQL_FOUND)

