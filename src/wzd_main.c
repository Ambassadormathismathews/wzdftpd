#include "wzd.h"

#include <regex.h>

int stay_foreground=0;

void display_usage(void)
{
  fprintf(stderr,"Usage:\r\n");
  fprintf(stderr,"\t -h        - Display this text \r\n");
#if DEBUG
  fprintf(stderr,"\t -b        - Force background \r\n");
#endif
  fprintf(stderr,"\t -d        - Delete IPC if present (Linux only) \r\n");
  fprintf(stderr,"\t -f <file> - Load alternative config file \r\n");
  fprintf(stderr,"\t -s        - Stay in foreground \r\n");
  fprintf(stderr,"\t -V        - Show version \r\n");
}

void cleanup_shm(void)
{
  char buffer[1024];
  char value[1024];
  char varname[1024];
  char *ptr;
  regex_t reg_line;
  regmatch_t regmatch[3];
  FILE *configfile;
  int length, err;
  unsigned long shm_key=0x1331c0d3;

  configfile = fopen("wzd.cfg","r");
  if (!configfile)
    return;

  while (fgets(buffer,1024,configfile))
  {
    ptr = buffer;
    length = strlen(buffer); /* fgets put a '\0' at the end */
    /* trim leading spaces */
    while (((*ptr)==' ' || (*ptr)=='\t') && (length-- > 0))
      ptr++;
    if ((*ptr)=='#' || length<=1)       /* comment and empty lines */
      continue;

    /* TODO if line contains a " and is not ended, it is a multi-line */
    /* TODO replace special chars (\n,\t,\xxx,etc) */

    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    if (length <= 0) continue;

    reg_line.re_nsub = 2;
    err = regcomp (&reg_line, "^([-]?[a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
    if (err) {
      out_log(LEVEL_CRITICAL,"Regexp could not compile (file %s line %d)\n",__FILE__,__LINE__);
      out_log(LEVEL_CRITICAL,"Possible error cause: bad libc installation\n");
      exit (1);
    }

    err = regexec(&reg_line,ptr,3,regmatch,0);
    if (err) {
      out_log(LEVEL_HIGH,"Line '%s' does not respect config line format - ignoring\n",buffer);
    } else {
      memcpy(varname,ptr+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
      varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
      memcpy(value,ptr+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
      value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

      if (strcasecmp(varname,"shm_key")==0) {
	unsigned long new_key=0;
	errno = 0;
	new_key = strtoul(value,(char**)NULL,0);
	if (errno == ERANGE) return;
	shm_key = new_key;
      }
    }
  }
  fclose(configfile);

  wzd_shm_cleanup(shm_key-1);
  wzd_shm_cleanup(shm_key);
}


int main_parse_args(int argc, char **argv)
{
  int opt;

  /* please keep options ordered ! */
  while ((opt=getopt(argc, argv, "hbdf:sV")) != -1) {
    switch((char)opt) {
    case 'h':
      display_usage();
      return 1;
    case 'b':
      stay_foreground = 0;
      break;
    case 'd':
/*      readConfigFile("wzd.cfg");*/
      cleanup_shm();
      return 1;
    case 's':
      stay_foreground = 1;
      break;
    case 'V':
      fprintf(stderr,"%s build %lu\n",WZD_VERSION_STR,(unsigned long)WZD_BUILD_NUM);
      return 1;
    }
  }

  return 0;
}



int main(int argc, char **argv)
{
  int ret;
  int forkresult;

#if DEBUG
  stay_foreground = 1;
#endif

  if (argc > 1) {
    ret = main_parse_args(argc,argv);
    if (ret) {
      return 0;
    }
  }

  if (!stay_foreground) {
    forkresult = fork();

    if ((int)forkresult == -1)
      out_err(LEVEL_CRITICAL,"Could not fork into background\n");
    if ((int)forkresult != 0)
      exit(0);
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
