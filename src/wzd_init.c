#include "wzd.h"

#include <regex.h>

#define BUFSIZE	1024

int set_default_options(void)
{
  mainConfig.backend.handle=NULL;

  mainConfig.port = 21;
  mainConfig.max_threads=32;

  mainConfig.logfilename = malloc(256);
  strcpy(mainConfig.logfilename,"wzd.log");

  mainConfig.logfilemode = malloc(3);
  strcpy(mainConfig.logfilemode,"a");

  mainConfig.logfile = NULL;

  mainConfig.loglevel=LEVEL_LOWEST;

  return 0;
}

int parseVariable(const char *varname, const char *value);

int readConfigFile(const char *fileName)
{
	int err;
	FILE * configfile;
	char buffer[BUFSIZE];
	char varname[BUFSIZE];
	char value[BUFSIZE];
	char * ptr;
	int length;
	regex_t reg_line;
	regmatch_t regmatch[3];

	init_default_messages();
	set_default_options();

	configfile = fopen(fileName,"r");
	if (!configfile)
	  return 0;

	while (fgets(buffer,BUFSIZE,configfile))
	{
		ptr = buffer;
		length = strlen(buffer); /* fgets put a '\0' at the end */
		/* trim leading spaces */
		while (((*ptr)==' ' || (*ptr)=='\t') && (length-- > 0))
		  ptr++;
		if ((*ptr)=='#' || length<=1)	/* comment and empty lines */
		  continue;

		/* trim trailing space, because fgets keep a \n */
		*(ptr+length-1) = '\0';
		length--;

		reg_line.re_nsub = 2;
		err = regcomp (&reg_line, "^([a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
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

		  err = parseVariable(varname,value);
		  if (err) {
		    out_log(LEVEL_HIGH,"Line '%s' is not a valid config line (probably var name mistake) - ignoring\n",buffer);
		  }
		}
	}
	


	fclose(configfile);
/*exit(1);*/
	return 0;
}

int parseVariable(const char *varname, const char *value)
{
  int i;

  /* PORT (int)
   * 2 remarks:
   * - use strtol (instead of atoi) to detect errors
   * - base can be 10 (default), 16 ( 0xnum ) or 8 ( 0num )
   */
  if (strcasecmp("port",varname)==0)
  {
    i = strtol(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (i < 1 || i > 65535) {
      out_log(LEVEL_HIGH,"port must be between 1 and 65535 inclusive\n");
      return 1;
    }
    out_log(LEVEL_INFO,"******* changing port: new value %d\n",i);
    mainConfig.port = i;
    return 0;
  }
  /* MAX_THREADS (int)
   * must be between 1 and 2000
   */
  if (strcasecmp("max_threads",varname)==0)
  {
    i = strtol(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (i < 1 || i > 2000) {
      out_log(LEVEL_HIGH,"max_threads must be between 1 and 2000 inclusive\n");
      return 1;
    }
    out_log(LEVEL_INFO,"******* changing max_threads: new value %d\n",i);
    mainConfig.max_threads = i;
    return 0;
  }
  /* BACKEND (string)
   * name of a .so
   */
  if (strcasecmp("backend",varname)==0)
  {
    out_log(LEVEL_INFO,"trying backend; '%s'\n",value);
    i = backend_validate(value);
    if (!i) {
      if (mainConfig.backend.handle == NULL) {
        i = backend_init(value);
      } else { /* multiple backends ?? */
	i=0;
      }
    }
    return i;
  }
  return 1;
}
