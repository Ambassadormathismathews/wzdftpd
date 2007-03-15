SUBDIRS(plaintext)

IF(MYSQL_FOUND)
  add_subdirectory(mysql)
ENDIF(MYSQL_FOUND)

IF(SQLITE3_FOUND)
  add_subdirectory(sqlite)
ENDIF(SQLITE3_FOUND)

IF(POSTGRESQL_FOUND)
  add_subdirectory(pgsql)
ENDIF(POSTGRESQL_FOUND)

