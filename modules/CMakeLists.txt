add_subdirectory(debug)

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
