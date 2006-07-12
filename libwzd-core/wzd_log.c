/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/** \file wzd_log.c
 * @brief Contains routines to log files.
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <io.h>
#else
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <syslog.h>
#endif

#include <fcntl.h> /* O_WRONLY */

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

struct wzd_log_entry_t {
  int fd;
  int syslog;
};

static struct wzd_log_entry_t _log_channels[MAX_LOG_CHANNELS];

int log_init(void)
{
  int i;

  for (i=0; i<MAX_LOG_CHANNELS; i++) {
    _log_channels[i].fd = -1;
    _log_channels[i].syslog = 0;
  }

  return 0;
}

int log_open(const char * filename, int filemode)
{
  int fd;

  fd = open(filename, filemode, 0640);
  if (fd)
    FD_REGISTER(fd,"Log");

  return fd;
}

void log_close(int fd)
{
#ifdef DEBUG
  if (fd == 1 /* stdout */ || fd == 2 /* stderr */) return;
#endif
  if (fd == -1) return;

  FD_UNREGISTER(fd,"Log");
  close(fd);
}

void log_fini(void)
{
  int i,j,fd;

  for (i=0; i<MAX_LOG_CHANNELS; i++)
    if (_log_channels[i].fd != -1) {
      fd = _log_channels[i].fd;
      for (j=i; j<MAX_LOG_CHANNELS; j++)
        if (_log_channels[j].fd == fd) _log_channels[j].fd = -1;
#ifdef DEBUG
      if (fd == 1 /* stdout */ || fd == 2 /* stderr */) continue;
#endif
      FD_UNREGISTER(fd,"Log");
      close(fd);
    }
}

/* NOTE we are forced to open log in lib, because of win32
 * memory management
 */
int log_open_old(const char *filename, int filemode)
{
  int fd;

  fd = open(filename, filemode, 0640);
  if (fd < 0)
    return -1;
  mainConfig->logfile = fdopen(fd,"a");
  if (!mainConfig->logfile) return 1;
  return 0;
}

void log_close_old(void)
{
  if (mainConfig->logfile)
    fclose(mainConfig->logfile);
  mainConfig->logfile = NULL;
}

/** \brief Get file descriptor asociated to log level
 *
 * Get file decriptor corresponding to all messages sent to the
 * log level.
 */
int log_get(unsigned int level)
{
  if (level >= MAX_LOG_CHANNELS) return -1;

  return _log_channels[level].fd;
}

int log_set(unsigned int level, int fd)
{
  unsigned int i, count;

  if (level >= MAX_LOG_CHANNELS) return -1;

  if (_log_channels[level].fd > 0) {
    count = 0;

    for (i=0; i<MAX_LOG_CHANNELS; i++) {
      if (_log_channels[i].fd == _log_channels[level].fd)
        count++;
    }
    if (count == 1) {
      log_close(_log_channels[level].fd);
    }
  }

  _log_channels[level].fd = fd;

  return 0;
}

int log_set_syslog(unsigned int level, int syslog_value)
{
  if (level >= MAX_LOG_CHANNELS) return -1;

  _log_channels[level].syslog = syslog_value;

  return 0;
}

void out_log(int level,const char *fmt,...)
{
  int prior=0;
  va_list argptr;
  char buffer[4096];
  char datestr[128];
  time_t timeval;
  struct tm * ntime;

  /* new logging code */
  if (level >= MAX_LOG_CHANNELS) return;

  /* create timestamp */
  timeval = time(NULL);
  ntime = localtime( &timeval );
  (void)strftime(datestr,sizeof(datestr),"%b %d %H:%M:%S ",ntime);

  if (_log_channels[level].fd > 0 || _log_channels[level].syslog)
  {
    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
    vsnprintf(buffer,sizeof(buffer)-1,fmt,argptr);
    va_end (argptr);

    if (_log_channels[level].fd > 0) {
      write(_log_channels[level].fd, datestr, strlen(datestr));
      write(_log_channels[level].fd, buffer, strlen(buffer));
    }

#ifndef _WIN32
    if (_log_channels[level].syslog)
    {
      /* default priority: informational */
      prior = LOG_INFO;
      switch (level) {
        case LEVEL_CRITICAL:
          prior = LOG_ERR;
          break;
        case LEVEL_HIGH:
          prior = LOG_ERR;
          break;
        case LEVEL_NORMAL:
          prior = LOG_NOTICE;
          break;
        case LEVEL_INFO:
          prior = LOG_INFO;
          break;
        case LEVEL_FLOOD:
          prior = LOG_DEBUG;
          break;
        default:
          break;
      }

      syslog(prior,"%s",buffer);
    }
#endif
  }

#ifdef DEBUG
  {
    char new_format[1024];
    char msg_begin[120];
    char msg_end[20];

    msg_begin[0] = '\0';
    msg_end[0] = '\0';

    switch (level) {
      case LEVEL_CRITICAL:
        strcpy(msg_begin,CLR_BOLD);
        (void)strlcat(msg_begin,CLR_RED,sizeof(msg_begin));
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

    /* add timestamp */
    strlcat(msg_begin,datestr,sizeof(msg_begin));

    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
    snprintf(new_format,sizeof(new_format)-1,"%s%s%s",msg_begin,fmt,msg_end);
    vsnprintf(buffer,sizeof(buffer)-1,new_format,argptr);
    va_end (argptr);

    write(1 /* stderr */, buffer, strlen(buffer));
  }
#endif
}

#ifdef DEBUG
void out_err(int level, const char *fmt,...)
{
  va_list argptr;
  char msg_begin[120];
  char msg_end[20];
  char new_format[1024];
  char datestr[128];
  time_t timeval;
  struct tm * ntime;

  msg_begin[0] = '\0';
  msg_end[0] = '\0';

  if (!mainConfig || level >= mainConfig->loglevel) {

    { /* ! syslog */


      switch (level) {
        case LEVEL_CRITICAL:
          strcpy(msg_begin,CLR_BOLD);
          (void)strlcat(msg_begin,CLR_RED,sizeof(msg_begin));
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

      /* add timestamp */
      timeval = time(NULL);
      ntime = localtime( &timeval );
      (void)strftime(datestr,sizeof(datestr),"%b %d %H:%M:%S ",ntime);
      strlcat(msg_begin,datestr,sizeof(msg_begin));

      snprintf(new_format,1023,"%s%s%s",msg_begin,fmt,msg_end);

      /* XXX we can't use mainConfig, because it could be broken here */
      /*  if (level >= mainConfig->loglevel) {*/
      va_start(argptr,fmt); /* note: ansi compatible version of va_start */
      vfprintf(stderr,new_format,argptr);
      fflush(stderr);
      va_end (argptr);
      /*  }*/
    } /* syslog */
  } /* > loglevel ? */
}
#else
void out_err(int level, const char *fmt,...)
{
}
#endif

int xferlog_open(const char *filename, unsigned int filemode)
{
  int fd;
#if (defined (__FreeBSD__) && (__FreeBSD__ < 5)) || defined(WIN32) || defined(__APPLE__)
  fd = open(filename,O_WRONLY | O_CREAT | O_APPEND, filemode);
#else /* ! BSD */
  fd = open(filename,O_WRONLY | O_CREAT | O_APPEND | O_SYNC, filemode);
#endif /* BSD */
  return fd;
}

void xferlog_close(int fd)
{
  close(fd);
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
  (void)strftime(datestr,sizeof(datestr),"%a %b %d %H:%M:%S %Y",ntime);
  snprintf(buffer,2047,
      "%s %lu %s %" PRIu64 " %s %c %c %c %c %s ftp 1 * %c\n",
      datestr,
      (unsigned long)(time(NULL)-context->current_action.tm_start), /* transfer time */
      remote_host?remote_host:"(null)", /* remote-host */
      context->current_action.bytesnow, /* file-size */
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
  (void)write(mainConfig->xferlog_fd,buffer,strlen(buffer));
}

void log_message(const char *event, const char *fmt, ...)
{
  va_list argptr;
  char buffer[2048];
  char datestr[128];
  time_t timeval;
  struct tm * ntime;

  va_start(argptr,fmt); /* note: ansi compatible version of va_start */
  vsnprintf(buffer,2047,fmt,argptr);
  va_end (argptr);

  timeval = time(NULL);
  ntime = localtime( &timeval );
  (void)strftime(datestr,sizeof(datestr),"%a %b %d %H:%M:%S %Y",ntime);
  out_log(LEVEL_NORMAL,"%s %s: %s\n",
      datestr,
      event,
      buffer
      );
}

int str2loglevel(const char *s)
{
  if (strcasecmp(s,"lowest")==0) return LEVEL_LOWEST;
  else if (strcasecmp(s,"flood")==0) return LEVEL_FLOOD;
  else if (strcasecmp(s,"info")==0) return LEVEL_INFO;
  else if (strcasecmp(s,"normal")==0) return LEVEL_NORMAL;
  else if (strcasecmp(s,"high")==0) return LEVEL_HIGH;
  else if (strcasecmp(s,"critical")==0) return LEVEL_CRITICAL;
  return -1;
}

const char * loglevel2str(int l)
{
  switch (l) {
  case LEVEL_LOWEST: return "lowest";
  case LEVEL_FLOOD: return "flood";
  case LEVEL_INFO: return "info";
  case LEVEL_NORMAL: return "normal";
  case LEVEL_HIGH: return "high";
  case LEVEL_CRITICAL: return "critical";
  }
  return "";
}

