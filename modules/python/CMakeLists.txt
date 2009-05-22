INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	${PYTHON_INCLUDE_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/modules/python)

SET(libwzd_python_SOURCES 
  libwzd_python.c
  libwzd_python_wzd.c
  libwzd_python_wzd_exc.c
  libwzd_python_wzd_group.c
  libwzd_python_wzd_user.c
  libwzd_python_wzd_shm.c
  libwzd_python_wzd_vfs.c
)

ADD_LIBRARY (libwzd_python SHARED
	${libwzd_python_SOURCES}
	python.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_python PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(python_LIBS libwzd_core ${PYTHON_LIBRARIES})

TARGET_LINK_LIBRARIES (libwzd_python ${python_LIBS})

INSTALL(TARGETS libwzd_python DESTINATION ${MODULES_INSTALL_PATH})

