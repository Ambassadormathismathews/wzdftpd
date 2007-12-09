# Since Visual Studio 2005, you get a bunch of warnings when using
# strncpy. Make it quiet !
IF(MSVC)
  ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE)
ENDIF(MSVC)

# Use this on platforms where dlopen() is in -ldl
IF (HAVE_LDL)
  SET(EXTRA_LIBS "dl")
ENDIF (HAVE_LDL)

IF (CMAKE_COMPILER_IS_GNUCC)
  # Ignore external flags for the debug build so there aren't conflicts
  SET(CMAKE_C_FLAGS_DEBUG "-std=gnu99 -pedantic -Wall -O1 -ggdb")
  # Allow external flags for the release build but try to force C99
  SET(CMAKE_C_FLAGS_RELEASE "-std=gnu99 ${CMAKE_C_FLAGS_RELEASE}")
ENDIF (CMAKE_COMPILER_IS_GNUCC)
