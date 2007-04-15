SET (txt_FILES file_ginfo.txt file_groups.txt file_group.txt
    file_help.txt file_rules.txt file_swho.txt file_users.txt
    file_user.txt file_vfs.txt file_who.txt)

INCLUDE_DIRECTORIES (${WZDFTPD_SOURCE_DIR}
        ${WZDFTPD_SOURCE_DIR}/libwzd-core
        ${WZDFTPD_BINARY_DIR}
        )

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

link_directories (${WZDFTPD_BINARY_DIR}/libwzd-core)

add_executable (wzdftpd wzd_main.c
	wzd_opts.h
	wzd_ServerThread.c wzd_ServerThread.h
	)

# Link the executable to the libwzd-core library.
target_link_libraries (wzdftpd libwzd_core ${EXTRA_LIBS})

IF (NOT SKIP_INSTALL_RPATH)
  SET_TARGET_PROPERTIES(wzdftpd PROPERTIES INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF (NOT SKIP_INSTALL_RPATH)

INSTALL(TARGETS wzdftpd RUNTIME DESTINATION "${SBIN_INSTALL_PATH}")

INSTALL(FILES users.sample DESTINATION ${CONF_INSTALL_PATH})
INSTALL(FILES ${WZDFTPD_BINARY_DIR}/wzdftpd/wzd.cfg.sample DESTINATION ${CONF_INSTALL_PATH})
INSTALL(FILES ${txt_FILES} wzd.pem DESTINATION ${CONF_INSTALL_PATH})
#INSTALL(CODE "FILE(MAKE_DIRECTORY \"${localstatedir}/log/wzdftpd\")")
INSTALL(DIRECTORY  DESTINATION "${localstatedir}/log/wzdftpd")
