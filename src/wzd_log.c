#include "wzd.h"

void out_log(int level,const char *fmt,...)
{
  va_list argptr;
  char msg_begin[20];
  char msg_end[20];

  msg_begin[0] = '\0';
  msg_end[0] = '\0';

  if (level >= mainConfig->loglevel) {
    char new_format[1024];

#ifdef DEBUG
    switch (level) {
    case LEVEL_CRITICAL:
      strcpy(msg_begin,CLR_BOLD);
      strcat(msg_begin,CLR_RED);
      strcpy(msg_end,CLR_NOCOLOR);
      break;
    case LEVEL_HIGH:
      strcpy(msg_begin,CLR_RED);
      strcpy(msg_end,CLR_NOCOLOR);
      break;
    case LEVEL_NORMAL:
      strcpy(msg_begin,CLR_GREEN);
      strcpy(msg_end,CLR_NOCOLOR);
      break;
    case LEVEL_INFO:
      strcpy(msg_begin,CLR_BLUE);
      strcpy(msg_end,CLR_NOCOLOR);
      break;
    case LEVEL_FLOOD:
      strcpy(msg_begin,CLR_CYAN);
      strcpy(msg_end,CLR_NOCOLOR);
      break;
    default:
      break;
    }
#endif

    snprintf(new_format,1023,"%s%s%s",msg_begin,fmt,msg_end);
    
    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
#ifdef DEBUG
    if (mainConfig->logfile) {
      vfprintf(stdout,new_format,argptr);
/*      vfprintf(mainConfig->logfile,fmt,argptr);
      fflush(mainConfig->logfile);*/
    } else { /* security - will be used iff log is not opened at this time */
      vfprintf(stderr,new_format,argptr);
    }
#else
    if (mainConfig->logfile) {
      vfprintf(mainConfig->logfile,fmt,argptr);
      fflush(mainConfig->logfile);
    }
#endif
  }
}

void out_err(int level, const char *fmt,...)
{
  va_list argptr;
  char msg_begin[20];
  char msg_end[20];
  char new_format[1024];

  msg_begin[0] = '\0';
  msg_end[0] = '\0';

  switch (level) {
  case LEVEL_CRITICAL:
    strcpy(msg_begin,CLR_BOLD);
    strcat(msg_begin,CLR_RED);
    strcpy(msg_end,CLR_NOCOLOR);
    break;
  case LEVEL_HIGH:
    strcpy(msg_begin,CLR_RED);
    strcpy(msg_end,CLR_NOCOLOR);
    break;
  case LEVEL_NORMAL:
    strcpy(msg_begin,CLR_GREEN);
    strcpy(msg_end,CLR_NOCOLOR);
    break;
  case LEVEL_INFO:
    strcpy(msg_begin,CLR_BLUE);
    strcpy(msg_end,CLR_NOCOLOR);
    break;
  case LEVEL_FLOOD:
    strcpy(msg_begin,CLR_CYAN);
    strcpy(msg_end,CLR_NOCOLOR);
    break;
  default:
    break;
  }

  snprintf(new_format,1023,"%s%s%s",msg_begin,fmt,msg_end);

  /* XXX we can't use mainConfig, because it could be broken here */
/*  if (level >= mainConfig->loglevel) {*/
    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
    vfprintf(stderr,new_format,argptr);
/*  }*/
}
