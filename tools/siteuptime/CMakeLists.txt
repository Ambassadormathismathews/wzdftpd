INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd)

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/libwzd)

ADD_EXECUTABLE (siteuptime siteuptime.c)

# Link the executable to the libwzd-core library.
TARGET_LINK_LIBRARIES (siteuptime libwzd)

SET_TARGET_PROPERTIES(siteuptime PROPERTIES INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
INSTALL(TARGETS siteuptime RUNTIME DESTINATION bin)
