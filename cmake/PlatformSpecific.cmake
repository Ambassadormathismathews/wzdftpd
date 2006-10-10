# Since Visual Studio 2005, you get a bunch of warnings when using
# strncpy. Make it quiet !
IF(WIN32)
  ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE)
ENDIF(WIN32)

# Use this on platforms where dlopen() is in -ldl
IF (NOT WIN32)
  SET(EXTRA_LIBS "dl")
ENDIF (NOT WIN32)
