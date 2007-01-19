SET (man1_FILES siteconfig.1 siteuptime.1 sitewho.1 wzd-config.1)
SET (man8_FILES wzdftpd.8)

INSTALL(FILES ${man1_FILES} DESTINATION ${MAN_INSTALL_PATH}/man1)
INSTALL(FILES ${man8_FILES} DESTINATION ${MAN_INSTALL_PATH}/man8)
