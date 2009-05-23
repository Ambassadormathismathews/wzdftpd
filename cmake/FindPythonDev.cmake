# - Find Python 
# Find the Python includes and library
# This module defines
#  PYTHON_INCLUDE_DIR, where to find Python.h
#  PYTHON_LIBRARIES, the libraries needed to use Python.
#  PYTHON_FOUND, If false, do not try to use Python.
#
# Copyright (c) 2007, mathgl, <mathgl@free.fr>
#
# Redistribution and use is allowed according to the terms of the BSD license.

if(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)
   set(PYTHON_FOUND TRUE)
else(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)
  
  #find include
  find_path(PYTHON_INCLUDE_DIR Python.h
      /usr/local/include/python2.6
      /usr/include/python2.6
      /usr/local/include/python2.5
      /usr/include/python2.5
      /usr/local/include/python2.4
      /usr/include/python2.4
  )

  #find libraries
  find_library(PYTHON_LIBRARIES NAMES python2.6 python2.5 python2.4
      PATHS
      /usr/lib
      /usr/local/lib
  )

  #check and display
  if(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)
    set(PYTHON_FOUND TRUE)
    message(STATUS "Found Python: ${PYTHON_INCLUDE_DIR}, ${PYTHON_LIBRARIES}")
  else(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)
    set(PYTHON_FOUND FALSE)
    message(STATUS "Python not found.")
  endif(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)

  mark_as_advanced(PYTHON_INCLUDE_DIR PYTHON_LIBRARIES)

endif(PYTHON_INCLUDE_DIR AND PYTHON_LIBRARIES)

