#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

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

void out_xferlog(wzd_context_t * context, int is_complete)
{
  char buffer[2048];
  char datestr[128];
  time_t timeval;
  struct tm * ntime;
  const char * remote_host;
  struct hostent *h;
  char * username;

  if (mainConfig->xferlog_fd == -1) return;
  
  h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),AF_INET);
  if (h==NULL)
    remote_host = inet_ntoa( *((struct in_addr*)context->hostip) );
  else
    remote_host = h->h_name;
  username = GetUserByID(context->userid)->username;
  timeval = time(NULL);
  ntime = localtime( &timeval );
  strftime(datestr,sizeof(datestr),"%a %b %d %H:%M:%S %Y",ntime);
  snprintf(buffer,2047,"%s %lu %s %lu %s %c %c %c %c %s ftp 1 * %c\n",
      datestr,
      time(NULL)-context->current_action.tm_start, /* transfer time */
      remote_host?remote_host:"(null)", /* remote-host */
      (unsigned long)context->current_action.bytesnow, /* file-size */
      context->current_action.arg, /* filename */
      'b', /* transfer type: b(inary) / a(scii) */
      '_', /* special action flag: C(ompressed), U(ncompressed),
	      T(ar'ed) _ (no action) */
      (context->current_action.token==TOK_RETR)?'o':'i',
        /* direction: o (outgoing) i (incoming) */
      'r', /* access-mode: a (anonymous) g (guest) r (real-user) */
      username,
      is_complete?'c':'i' /* c (complete) i (incomplete) */
      );
  write(mainConfig->xferlog_fd,buffer,strlen(buffer));
}
