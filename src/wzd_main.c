#include "wzd.h"

wzd_config_t mainConfig;

int main(int argc, char **argv)
{
  int ret;

  ret = readConfigFile("wzd.cfg"); /* XXX */

  mainConfig.logfile = fopen(mainConfig.logfilename,mainConfig.logfilemode);

#if SSL_SUPPORT
  ret = tls_init();
  if (ret) {
    out_log(LEVEL_CRITICAL,"TLS subsystem could not be initialized.\n");
    return 1;
  }
#endif

  ret = runMainThread(argc,argv);

  fclose(mainConfig.logfile);

  return ret;
}
