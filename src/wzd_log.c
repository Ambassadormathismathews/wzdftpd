#include "wzd.h"

void out_log(int level,const char *fmt,...)
{
	va_list argptr;

	if (level >= mainConfig->loglevel) {
		va_start(argptr,fmt); /* note: ansi compatible version of va_start */
		if (mainConfig->logfile) {
			vfprintf(stdout,fmt,argptr);
/*			vfprintf(mainConfig->logfile,fmt,argptr);
			fflush(mainConfig->logfile);*/
		} else { /* security - will be used iff log is not opened at this time */
			vfprintf(stderr,fmt,argptr);
		}
	}
}

void out_err(int level, const char *fmt,...)
{
  va_list argptr;

  if (level >= mainConfig->loglevel) {
    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
    vfprintf(stderr,fmt,argptr);
  }
}
