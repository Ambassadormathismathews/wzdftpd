#include "wzd.h"

wzd_config_t *  mainConfig;

wzd_config_t * getlib_mainConfig(void)
{ return mainConfig; }

void setlib_mainConfig(wzd_config_t *c)
{ mainConfig = c; }

void libtest(void)
{
/*  fprintf(mainConfig->logfile,"TEST LIB OK\n");*/
  out_log(LEVEL_CRITICAL,"TEST LIB OK\n");
}
