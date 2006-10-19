INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	${PERL_INCLUDE_PATH}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

IF(PERL_EXTRA_C_FLAGS)
  ADD_DEFINITIONS(${PERL_EXTRA_C_FLAGS})
ENDIF(PERL_EXTRA_C_FLAGS)

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/modules/perl)

SET(libwzd_perl_SOURCES libwzd_perl.c)

ADD_LIBRARY (libwzd_perl SHARED
	${libwzd_perl_SOURCES}
	perl.def
	)

SET_SOURCE_FILES_PROPERTIES(${libwzd_perl_SOURCES} COMPILE_FLAGS "${PERL_EXTRA_C_FLAGS}")

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_perl PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(perl_LIBS libwzd_core)

# Workaround: we need to use DynaLoader.a, but cmake provides
# no way to link to a static library (or add it to objects files)
# So we copy the file in the build directory with a correct name, so we are
# able to use TARGET_LINK_LIBRARIES
IF (NOT WIN32)
  IF(PERL_EXTRA_LD_FLAGS)
    MACRO_ADD_LINK_FLAGS(libwzd_perl "${PERL_EXTRA_LD_FLAGS}")
  ENDIF(PERL_EXTRA_LD_FLAGS)

  ADD_CUSTOM_TARGET(libDynaLoader.a COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${PERL_DYNALOADER}
    libDynaLoader.a)
  ADD_DEPENDENCIES(libwzd_perl libDynaLoader.a)
  SET(perl_LIBS ${perl_LIBS} DynaLoader)
ENDIF (NOT WIN32)

IF(PERL_LIBRARY)
  SET(perl_LIBS ${perl_LIBS} ${PERL_LIBRARY})
ENDIF(PERL_LIBRARY)

TARGET_LINK_LIBRARIES (libwzd_perl ${perl_LIBS})

INSTALL(TARGETS libwzd_perl DESTINATION ${MODULES_INSTALL_PATH})
