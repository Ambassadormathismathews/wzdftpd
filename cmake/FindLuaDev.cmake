# - Find Lua 5.1 
# Find the Lua includes and library
# This module defines
#  LUA51_INCLUDE_DIR, where to find lua.h.
#  LUA51_LIBRARIES, the libraries needed to use Lua.
#  LUA51_FOUND, If false, do not try to use Lua.
#
# Copyright (c) 2006, mathgl <mathgl67@gmail.com>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

if(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)
   set(LUA51_FOUND TRUE)

else(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)

  find_path(LUA51_INCLUDE_DIR lua.h
      /usr/include/lua5.1
      /usr/local/include/lua5.1
      $ENV{SystemDrive}/Lua/include
      $ENV{ProgramFiles}/Lua/include
      )

  find_library(LUA51_LIBRARIES NAMES lua5.1
      PATHS
      /usr/lib
      /usr/local/lib
      $ENV{SystemDrive}/Lua
      $ENV{ProgramFiles}/Lua
      )

  if(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)
    set(LUA51_FOUND TRUE)
    message(STATUS "Found Lua 5.1: ${LUA51_INCLUDE_DIR}, ${LUA51_LIBRARIES}")
  else(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)
    set(LUA51_FOUND FALSE)
    message(STATUS "Lua 5.1 not found.")
  endif(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)

  mark_as_advanced(LUA51_INCLUDE_DIR LUA51_LIBRARIES)

endif(LUA51_INCLUDE_DIR AND LUA51_LIBRARIES)
