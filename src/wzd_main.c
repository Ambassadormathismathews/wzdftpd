#include "wzd.h"

void display_usage(void)
{
  fprintf(stderr,"Usage:\r\n");
  fprintf(stderr,"\t -h        - Display this text \r\n");
  fprintf(stderr,"\t -d        - Delete IPC if present (Linux only) \r\n");
  fprintf(stderr,"\t -f <file> - Load alternative config file \r\n");
}

void cleanup_shm(void)
{
  wzd_shm_cleanup(mainConfig->shm_key);
}


int main_parse_args(int argc, char **argv)
{
  int opt;

  while ((opt=getopt(argc, argv, "hdf:")) != -1) {
    switch(tolower((char)opt)) {
    case 'h':
      display_usage();
      return 1;
    case 'd':
      readConfigFile("wzd.cfg");
      cleanup_shm();
      return 1;
    }
  }

  return 0;
}



int main(int argc, char **argv)
{
  int ret;

  if (argc > 1) {
    ret = main_parse_args(argc,argv);
    if (ret) {
      return 0;
    }
  }

  ret = readConfigFile("wzd.cfg"); /* XXX */

  mainConfig->logfile = fopen(mainConfig->logfilename,mainConfig->logfilemode);

#if SSL_SUPPORT
  ret = tls_init();
  if (ret) {
    out_log(LEVEL_CRITICAL,"TLS subsystem could not be initialized.\n");
    return 1;
  }
#endif

  ret = runMainThread(argc,argv);


  /* we should never pass here - see wzd_ServerThread.c */

  return ret;
}
