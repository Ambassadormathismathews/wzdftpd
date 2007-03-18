SET(libwzd_core_arch_pub_HEADERS
	bsd.h
	win32.h
   )

INSTALL(FILES ${libwzd_core_arch_pub_HEADERS} DESTINATION ${HEADERS_INSTALL_PATH}/wzdftpd/libwzd-core/arch)
