#include "wzd.h"

wzd_config_t *  mainConfig;
wzd_context_t * context_list;

wzd_config_t * getlib_mainConfig(void)
{ return mainConfig; }

void setlib_mainConfig(wzd_config_t *c)
{ mainConfig = c; }

wzd_context_t * getlib_contextList(void)
{ return context_list; }

void setlib_contextList(wzd_context_t *c)
{ context_list = c; }

void libtest(void)
{
/*  fprintf(mainConfig->logfile,"TEST LIB OK\n");*/
  out_log(LEVEL_CRITICAL,"TEST LIB OK\n");
}
