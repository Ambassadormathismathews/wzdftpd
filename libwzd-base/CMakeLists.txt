SET(libwzd_base_pub_HEADERS
	dlist.h
	hash.h
	list.h
	stack.h
	strpcpy.h
	wzd_strlcat.h
	wzd_strtok_r.h
   )

INSTALL(FILES ${libwzd_base_pub_HEADERS} DESTINATION ${HEADERS_INSTALL_PATH}/wzdftpd/libwzd-base)
