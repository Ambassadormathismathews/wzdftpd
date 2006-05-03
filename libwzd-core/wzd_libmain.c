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

#include "wzd_all.h"

#ifndef WZD_USE_PCH
#include <stdio.h>
#include <string.h>

#include "wzd_structs.h"

#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_mutex.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

wzd_config_t *  mainConfig;
List * context_list;
static uid_t _wzd_server_uid;
static gid_t _wzd_server_gid;

wzd_mutex_t	* limiter_mutex;
wzd_mutex_t	* server_mutex = NULL;

wzd_mutex_t     * mutex_set[SET_MUTEX_NUM];

unsigned long mutex_set_key[SET_MUTEX_NUM] = {
  0x22005400,
  0x22005401,
  0x22005402,
  0x22005403,
  0x22005404,
  0x22005405,
  0x22005406,
  0x22005407,
  0x22005408,
  0x22005409,
  0x2200540a,
};

time_t          server_time;


const char * wzd_get_version(void)
{
  return VERSION;
}

const char * wzd_get_version_long(void)
{
  return WZD_VERSION_STR;
}

wzd_config_t * getlib_mainConfig(void)
{ return mainConfig; }

void setlib_mainConfig(wzd_config_t *c)
{ mainConfig = c; }

List * getlib_contextList(void)
{ return context_list; }

void setlib_contextList(List *c)
{ context_list = c; }

gid_t getlib_server_gid(void)
{ return _wzd_server_gid; }

void setlib_server_gid(gid_t gid)
{ _wzd_server_gid = gid; }

int getlib_server_uid(void)
{ return _wzd_server_uid; }

void setlib_server_uid(int uid)
{ _wzd_server_uid = uid; }

void libtest(void)
{
  out_log(LEVEL_CRITICAL,"TEST LIB OK\n");
}

int server_mutex_set_init(void)
{
  unsigned int i;

  for (i=0; i<SET_MUTEX_NUM; i++) {
    mutex_set[i] = wzd_mutex_create(mutex_set_key[i]);
  }

  return 0;
}

int server_mutex_set_fini(void)
{
  unsigned int i;

  for (i=0; i<SET_MUTEX_NUM; i++) {
    wzd_mutex_destroy(mutex_set[i]);
  }

  return 0;
}

/** called when SIGHUP received, need to restart the main server
 * (and re-read config file)
 * Currently loggued users are NOT kicked
 */
void server_restart(int signum)
{
#if 0
  wzd_config_t * config;
  int sock;
  int rebind=0;

  out_err(LEVEL_HIGH,"Sighup received\n");

  /* 1- Re-read config file, abort if error */
  config = readConfigFile(mainConfig->config_filename);
  if (!config) return;

  /* 2- Shutdown existing socket */
  if (config->port != mainConfig->port) {
    sock = mainConfig->mainSocket;
    close(sock);
    rebind = 1;
  }

  /* 3- Copy new config */
  {
    /* do not touch serverstop */
    /* do not touch backend */
    mainConfig->max_threads = config->max_threads;
    /* do not touch logfile */
    mainConfig->loglevel = config->loglevel;
    /* do not touch messagefile */
    /* mainSocket will be modified later */
    mainConfig->port = config->port;
    mainConfig->pasv_low_range = config->pasv_low_range;
    mainConfig->pasv_high_range = config->pasv_high_range;
    memcpy(mainConfig->pasv_ip, config->pasv_ip, sizeof(mainConfig->pasv_ip));
    mainConfig->login_pre_ip_check = config->login_pre_ip_check;
    /* reload pre-ip lists */
    /* reload vfs lists */
    vfs_free(&mainConfig->vfs);
    mainConfig->vfs = config->vfs;
    /* do not touch hooks */
    hook_free(&mainConfig->hook);
    mainConfig->hook = config->hook;
    /* do not touch modules */
#ifdef HAVE_OPENSSL
    /* what can we do with ssl ? */
    /* reload certificate ? */
#endif
    /* reload permission list ?? */
    /* reload global_ul_limiter ?? */
    /* reload global_dl_limiter ?? */
    mainConfig->site_config = config->site_config;
  }

  /* 4- Re-open server */

  /* create socket iff different ports ! */
  if (rebind) {
    sock = mainConfig->mainSocket = socket_make((const char *)mainConfig->ip,&mainConfig->port,mainConfig->max_threads);
    if (sock == -1) {
      out_log(LEVEL_CRITICAL,"Error creating socket %s:%d\n",
          __FILE__, __LINE__);
      serverMainThreadExit(-1);
    }
    {
      int one=1;

      if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
        out_log(LEVEL_CRITICAL,"setsockopt(SO_KEEPALIVE");
        serverMainThreadExit(-1);
      }
    }
    out_log(LEVEL_CRITICAL,"New file descriptor %d\n",mainConfig->mainSocket);
  }

  /* 5. Re-open log files */
  if ( !CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG) )
  {
    int fd;
    log_close();
    if (log_open(mainConfig->logfilename,mainConfig->logfilemode))
    {
      out_err(LEVEL_CRITICAL,"Could not reopen log file !!!\n");
    }
    if (mainConfig->xferlog_name) {
      xferlog_close(mainConfig->xferlog_fd);
      fd = xferlog_open(mainConfig->xferlog_name, 0600);
      if (fd==-1)
        out_log(LEVEL_HIGH,"Could not open xferlog file: %s\n",
            mainConfig->xferlog_name);
      mainConfig->xferlog_fd = fd;
    }
  }
#endif

  out_log(LEVEL_CRITICAL, " ** server_restart:  Not yet implemented\n");
}

/** \brief remove a context from the list */
int context_remove(List * context_list, wzd_context_t * context)
{
  ListElmt * elmnt;
  void * data;

  if (!context_list->head) return -1;
  wzd_mutex_lock(server_mutex);

  if (context == context_list->head->data)
  {
    list_rem_next(context_list, NULL, &data);
    context_free(context);
    wzd_mutex_unlock(server_mutex);
    return 0;
  }

  for (elmnt=context_list->head; elmnt; elmnt=list_next(elmnt))
  {
    if ( list_next(elmnt) && context == list_next(elmnt)->data )
    {
      list_rem_next(context_list, elmnt, &data);
      context_free(context);
      wzd_mutex_unlock(server_mutex);
      return 0;
    }
  }
  wzd_mutex_unlock(server_mutex);

  return -1;
}

/** \brief Frees a context
 */
void context_free(wzd_context_t * context)
{
  WZD_ASSERT_VOID(context != NULL);

  wzd_free(context->ident); context->ident = NULL;
  wzd_free(context->data_buffer); context->data_buffer = NULL;
  str_deallocate(context->current_action.command);
  ip_free(context->peer_ip);
  wzd_free(context);
}

