INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

IF(MYSQL_FOUND)
  ADD_DEFINITIONS(-DHAVE_MYSQL)
  INCLUDE_DIRECTORIES(${MYSQL_INCLUDE_DIR})
ENDIF(MYSQL_FOUND)

ADD_LIBRARY (libwzd_mysql SHARED
	libmysql_group.c
	libmysql_user.c
	libmysql.h
	libmysql_main.c
	libmysql.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_mysql PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(libwzd_mysql_LIBS libwzd_core)

IF(MYSQL_FOUND)
  SET(libwzd_mysql_LIBS ${libwzd_mysql_LIBS} ${MYSQL_LIBRARIES})
ENDIF(MYSQL_FOUND)

TARGET_LINK_LIBRARIES (libwzd_mysql ${libwzd_mysql_LIBS})

INSTALL(TARGETS libwzd_mysql DESTINATION ${BACKENDS_INSTALL_PATH})
