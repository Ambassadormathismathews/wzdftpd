#include <sys/time.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_libmain.h"
#include "wzd_log.h"

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
  out_log(LEVEL_CRITICAL,"TEST LIB OK\n");
}
