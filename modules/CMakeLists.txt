add_subdirectory(debug)

if(WITH_DUPECHECK)
  if(SQLITE3_FOUND)
    add_subdirectory(dupecheck)
  else(SQLITE3_FOUND)
    message("Could not find Sqlite3, not compiling libwzd-dupecheck.")
  endif(SQLITE3_FOUND)
endif(WITH_DUPECHECK)

if(WITH_SFV)
  add_subdirectory(sfv)
endif(WITH_SFV)

if(PERL_FOUND)
  add_subdirectory(perl)
endif(PERL_FOUND)

if(TCL_FOUND)
  add_subdirectory(tcl)
endif(TCL_FOUND)

if(ZEROCONF_FOUND)
  add_subdirectory(zeroconf)
endif(ZEROCONF_FOUND)
