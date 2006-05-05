/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2006  Pierre Chifflier
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

#include <stdio.h>
#include <string.h>

#if defined (WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h> /* htonl() */
#include <unistd.h>    /* fork */
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>

#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_mod.h>
#include <libwzd-core/wzd_string.h>

#ifndef WIN32
#include <pthread.h>
#endif
#include <libwzd-core/wzd_threads.h>

/* use this define if you want to use
   processes instead of threads. */
/* #define ZEROCONF_USE_PROCESS */

/* function prototypes and globals */
#include "libwzd_zeroconf.h"

/***********************/
MODULE_NAME(zeroconf);
MODULE_VERSION(101);

static void * routine (void * arg);

#ifdef ZEROCONF_USE_PROCESS
static pid_t pid_child = 0;
#else
static wzd_thread_t zeroconf_thread;
#endif

static int initialized = 0;

#ifdef USE_AVAHI
struct context *ctx = NULL;
#endif

#ifdef ZEROCONF_USE_PROCESS
static void sighandler(int sig)
{
  out_log(LEVEL_FLOOD,"zeroconf: received signal %d\n",sig);
#ifdef USE_AVAHI
  if (ctx)
    av_zeroconf_shutdown(ctx);
#elif defined (USE_HOWL)
  ho_zeroconf_unregister();
#elif defined (USE_BONJOUR)
  bo_zeroconf_unregister();
#endif
}
#endif

int WZD_MODULE_INIT(void)
{
  wzd_string_t * str;
  int err;
  int ret = 1;
  void * arg = NULL;
  const char *zeroconf_name = NULL;
  const char *zeroconf_username = NULL;
  const char *zeroconf_password = NULL;
  const char *zeroconf_path = NULL;
  unsigned long wzdftpd_port;

  if (initialized > 0) return 1;
  initialized++;

  /* the mDNS name that should be published */
  str = config_get_string(mainConfig->cfg_file, "ZEROCONF", "zeroconf_name", NULL);
  if (str) {
    zeroconf_name = strdup(str_tochar(str));
    str_deallocate(str);
  }

  /* TXT keys - see http://www.dns-sd.org/ServiceTypes.html */
  str = config_get_string(mainConfig->cfg_file, "ZEROCONF", "zeroconf_username", NULL);
  if (str) {
    zeroconf_username = strdup(str_tochar(str));
    str_deallocate(str);
  }

  str = config_get_string(mainConfig->cfg_file, "ZEROCONF", "zeroconf_password", NULL);
  if (str) {
    zeroconf_password = strdup(str_tochar(str));
    str_deallocate(str);
  }

  str = config_get_string(mainConfig->cfg_file, "ZEROCONF", "zeroconf_path", NULL);
  if (str) {
    zeroconf_path = strdup(str_tochar(str));
    str_deallocate(str);
  }

  /** the actual port
   * \todo determine port(s) dynamically from port = ...
   *  \todo support multiple ports
   */
  wzdftpd_port = config_get_integer(mainConfig->cfg_file, "ZEROCONF", "zeroconf_port", &err);
  if (err) {
    out_log(LEVEL_CRITICAL,"zeroconf: you must provide zeroconf_port=... in your config file\n");
    initialized = 0;
    return -1;
  }

#ifdef ZEROCONF_USE_PROCESS
  pid_child = fork();
  if (pid_child < 0) {
    out_log(LEVEL_CRITICAL,"zeroconf: could not create a new process\n");
    initialized = 0;
    return -1;
  }
  if (pid_child > 0) {
    return 0;
  }
  {
    sigset_t mask;
    sigfillset(&mask);
    ret = pthread_sigmask(SIG_UNBLOCK,&mask,NULL);
    if (pid_child < 0) {
      out_log(LEVEL_CRITICAL,"zeroconf: could not unblock pthread signals mask\n");
      initialized = 0;
      return -1;
    }
  }
# ifdef DEBUG
  /* We MUST close stdin, or the keyboard interrupts (like Ctrl+C) will be sent to both
   * the server and the zeroconf module
   */
  close(0);
# endif
  /* We have to override ALL the signals trapped in wzd_ServerThread.c
   * Since this process is created by fork(), it inheritates the file descriptors AND signal
   * handlers, so the server's handler would be called in the forked process !
   */
  signal(SIGINT,sighandler);
  signal(SIGTERM,sighandler);
  signal(SIGHUP,SIG_DFL);
#endif

#ifdef USE_BONJOUR
  /*
    TODO: This has to be tested on a OSX box. Especially whether it
    blocks the main wzdftpd loop/thread.
  */
  bo_zeroconf_setup(wzdftpd_port,
                    zeroconf_name,
                    zeroconf_username,
                    zeroconf_password,
                    zeroconf_path);
#elif defined (USE_AVAHI)
  assert(wzdftpd_port != 0); // the port should be defined in the config file

  ctx = av_zeroconf_setup(wzdftpd_port,
                          zeroconf_name,
                          zeroconf_username,
                          zeroconf_password,
                          zeroconf_path);
#elif defined (USE_HOWL)
  ho_zeroconf_setup(wzdftpd_port,
                    zeroconf_name,
                    zeroconf_username,
                    zeroconf_password,
                    zeroconf_path);
#endif

  out_log(LEVEL_INFO, "Module zeroconf loaded\n");

#ifdef ZEROCONF_USE_PROCESS
  routine(arg);
  exit (0);
#else
  ret = wzd_thread_create (&zeroconf_thread, NULL, &routine, arg);
#endif

  return 0;
}

void WZD_MODULE_CLOSE(void)
{
  int ret;
#ifndef ZEROCONF_USE_PROCESS
  void * thread_return;
#endif

  if (initialized) {
#ifdef ZEROCONF_USE_PROCESS
    kill(pid_child,SIGTERM);
#else
# ifdef USE_AVAHI
    if (ctx)
      av_zeroconf_shutdown(ctx);
# elif defined (USE_BONJOUR)
    bo_zeroconf_unregister();
# elif defined (USE_HOWL)
    ho_zeroconf_unregister();
# endif
#endif

#ifdef ZEROCONF_USE_PROCESS
    ret = wait4(pid_child, NULL, 0, NULL);
#else
    ret = wzd_thread_join(&zeroconf_thread, &thread_return);
#endif
  }

  out_log(LEVEL_INFO, "Module zeroconf unloaded\n");
}

static void * routine (void * arg)
{
#ifdef USE_AVAHI
  /* Now start the loop.
   * Note: run does not block the main loop. Tho It will create a new thread.
   */
  av_zeroconf_run(ctx);
# ifndef ZEROCONF_USE_PROCESS
# endif
#elif defined (USE_HOWL)
  ho_zeroconf_run();
#elif defined (USE_BONJOUR)
  bo_zeroconf_run();
#endif

  return NULL;
}
