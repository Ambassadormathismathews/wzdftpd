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

/** \file libwzd.c
 *  \brief Routines to access wzdftpd from applications
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include "../libwzd-base/wzd_strtok_r.h"

#include "libwzd.h"
#include "libwzd_pv.h"

#include "libwzd_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#else
# include <windows.h>
#endif

static int _has_code(const char *str);
static int _connect_server(void);

struct libwzd_config * _config=NULL;

static char * _host = NULL;
static int _port = 0;
static char * _user = NULL;
static char * _pass = NULL;
static unsigned long _options = 0;



/* wzd_parse_args
 *
 * parse command line arguments to detect libwzd-specific switches
 *
 * TODO we should find a way for user application to add arguments,
 * using hooks
 */
int wzd_parse_args(int argc, const char **argv)
{
  int optindex;
  int opt;
  int val;
  int i;
  int found;
  int option_is_long;
  const char * optarg=NULL;

  struct option_t {
    char * long_option;
    short has_argument;
    char * reserved;
    char short_option;
  };

  static struct option_t long_options[] =
  {
    { "user", 1, NULL, 'u' },
    { "pass", 1, NULL, 'w' },
    { "host", 1, NULL, 'h' },
    { "port", 1, NULL, 'p' },
    { "secure", 0, NULL, 's' },
    { "insecure", 0, NULL, 't' },
    { NULL, 0, NULL, 0 } /* sentinel */
  };

  for (optindex=1; optindex<argc; optindex++)
  {
    found = 0;
    opt = 0;
    if (argv[optindex][0]=='-') {
      /* argument */

      if (argv[optindex][1] == '-')
        option_is_long = 1;
      else
        option_is_long = 0;

      for (i=0; long_options[i].long_option!=NULL; i++)
      {
        if (( (option_is_long && strcmp(long_options[i].long_option,argv[optindex]+2)==0) )
            || (!option_is_long && long_options[i].short_option==argv[optindex][1]))
        { /* found */
          /* do we need an argument ? */
          if (long_options[i].has_argument>0) {
            optindex++;
            if (optindex>=argc) { /* missing argument */
              fprintf(stderr,"libwzd: missing argument for %s\n",argv[optindex-1]);
              return -1;
            }
            optarg = argv[optindex];
          }
          opt = long_options[i].short_option;
          found = 1;
        }
      }
    }
    else { /* not an option */
      continue;
    }

    if (!found) {
/*        fprintf(stderr,"libwzd; unknown option %s\n", argv[optindex]);*/
/*        return -1;*/
        continue;
    }

    switch ((char)opt) {
      case 'u':
        if (strlen(optarg)>0) {
          _user = strdup(optarg);
        }
        break;
      case 'w':
        if (strlen(optarg)>0) {
          _pass = strdup(optarg);
        }
        break;
      case 'h':
        if (strlen(optarg)>0) {
          _host = strdup(optarg);
        }
        break;
      case 'p':
        val = atoi(optarg); /* FIXME no test ... */
        _port = val;
        break;
      case 's':
        _options |= OPTION_TLS;
        break;
      case 't':
        _options |= OPTION_NOTLS;
        break;
    }
  }

  return 0;
}


void wzd_free_reply(wzd_reply_t *reply)
{
  int i;

  if (!reply) return;

  if (reply->data) {
    for (i=0; reply->data[i]!=NULL; i++)
      free(reply->data[i]);
    free(reply->data);
  }

  free(reply);
}


/** parameters are still being defined */
int wzd_init(void)
{
  /* 0- init structs */
  if (_config != NULL) return -1; /* init already done */
  _config = malloc(sizeof(struct libwzd_config));
  memset(_config,0,sizeof(struct libwzd_config));
  _config->host = (_host) ? _host : "localhost";
  _config->port = (_port) ? _port : 21;
  _config->user = (_user) ? _user : "wzdftpd";
  _config->pass = (_pass) ? _pass : "wzdftpd";
  _config->options = _options;

  /* 1- connect to server */
  if (_connect_server()<0) { free(_config); _config=NULL; return -1; }

  /* 2- fill static struct ? */

  return 0;
}

int wzd_fini(void)
{
  if (_host) { free(_host); _host = NULL; }
  if (_port) { _port = 0; }
  if (_user) { free(_user); _user = NULL; }
  if (_pass) { free(_pass); _pass = NULL; }

  if (_config) {
    wzd_free_reply( wzd_send_message("QUIT\r\n",6) );
#ifdef WIN32
    Sleep(100);
#else
    usleep(100);
#endif
    free(_config);
    _config = NULL;
  }

  return 0;
}

wzd_reply_t * wzd_send_message(const char *message, int msg_length)
{
  int ret;
  char * buffer;
  int buffer_length;
  wzd_reply_t * reply;

  if (!_config) return NULL;
  if (_config->connector.mode == CNT_NONE) return NULL;
  if (!_config->connector.read || !_config->connector.write) return NULL;
  if (!message) return NULL;

  /* check connection status ? */

  /* ensure last bytes of message are \r\n ? */

  ret = _config->connector.write(message,msg_length);
  if (ret != msg_length) return NULL;

  buffer_length = 4096;
  buffer = malloc(buffer_length+1);
  buffer[0] = '\0';
  ret = _config->connector.read(buffer,buffer_length);

  /* decode message if multi-line */
  reply = malloc(sizeof(wzd_reply_t));
  if (reply) {
    int count;
    int i;
    char *ptr, *line;

    reply->code = -1;

    /* get reply code */
    if (_has_code(buffer))
    {
      reply->code = (buffer[0]-'0')*100 + (buffer[1]-'0')*10 + (buffer[2]-'0');
    }

    /* how many lines in the reply ? */
    for (count=1, i=0; buffer[i] != '\0'; i++)
      if (buffer[i] == '\n') count++;

    /* allocate array of char * and decode reply */
    reply->data = malloc((count+1) * sizeof(char*));

    /* XXX FIXME we should ignore first and last lines if they contains no info */
    line = strtok_r(buffer,"\r\n",&ptr);
    reply->data[0] = malloc(strlen(line)+1);
    strncpy(reply->data[0],line,strlen(line)+1);
    for (i=1; i<count; i++)
    {
      line = strtok_r(NULL,"\r\n",&ptr);
      if (line)
      {
        reply->data[i] = malloc(strlen(line)+1);
        if (_has_code(reply->data[i]))
          strncpy(reply->data[i]+4,line,strlen(line)+1);
        else
          strncpy(reply->data[i],line,strlen(line)+1);
      } else
        reply->data[i] = NULL;
    }

    reply->data[count] = NULL;
  }

  free(buffer);

  return reply;
}

/*************** STATIC *******************/

/** connect to server and return file descriptor or -1
 */
static int _connect_server(void)
{
  int ret;

  if (!_config) return -1;

  /* 1- first, try named pipe ? */
  /* 2- try unix socket ? */
  /* 3- try socket ? */
  if ( (ret = server_try_socket()) >= 0 ) return ret;

  return -1; /* not connected */
}

static int _has_code(const char *str)
{
  if (!str || strlen(str)<4) return 0;

  if ( str[0] >= '0' && str[0] <= '9'
      && str[1] >= '0' && str[1] <= '9'
      && str[2] >= '0' && str[2] <= '9')
    return 1;

  return 0;
}
