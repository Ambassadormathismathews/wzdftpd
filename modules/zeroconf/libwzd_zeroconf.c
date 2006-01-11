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

#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include <arpa/inet.h> /* htonl() */
#include <sys/wait.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>

#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_mod.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_threads.h>

#define ZEROCONF_USE_PROCESS

/* function prototypes and globals */
#include "libwzd_zeroconf.h"

static void * routine (void * arg);
#ifdef ZEROCONF_USE_PROCESS
static pid_t pid_child = 0;
#else
static wzd_thread_t zeroconf_thread;
#endif

static int initialized = 0;

#ifdef ZEROCONF_USE_PROCESS
static void sighandler(int sig)
{
  out_log(LEVEL_FLOOD,"zeroconf: received signal %d\n",sig);
  doderegistration();
}
#endif

int WZD_MODULE_INIT(void)
{
  wzd_string_t * str;
  int err;
  int ret = 1;
  void * arg = NULL;
  const char *zeroconf_name = NULL;
  unsigned long wzdftpd_port;
#ifdef USE_AVAHI
  const AvahiPoll *poll_api = NULL;
  int error;
#endif
#ifdef USE_HOWL
  /* text records (username, password etc.) are currently not implemented */
  sw_text_record             text_record;
  sw_result                  result;
  sw_discovery_publish_id    id;
#endif

  if (initialized > 0) return 1;
  initialized++;

  str = config_get_string(mainConfig->cfg_file, "GLOBAL", "zeroconf_name", NULL);
  if (!str) {
    out_log(LEVEL_CRITICAL,"zeroconf: you must provide zeroconf_name=... in your config file\n");
    initialized = 0;
    return -1;
  }
  zeroconf_name = strdup(str_tochar(str));
  str_deallocate(str);

  wzdftpd_port = config_get_integer(mainConfig->cfg_file, "GLOBAL", "zeroconf_port", &err);
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
#ifdef DEBUG
  /* We MUST close stdin, or the keyboard interrupts (like Ctrl+C) will be sent to both
   * the server and the zeroconf module
   */
  close(0);
#endif
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
  DNSServiceRegistrationCreate(zeroconf_name,
                               "_ftp._tcp.",
                               "",
                               htonl(PostPortNumber),
                               "",
                               (DNSServiceRegistrationReply) reg_reply,
                               NULL);
#endif
#ifdef USE_AVAHI
  assert(zeroconf_name !=NULL); // the name should be defined in the config file
  assert(wzdftpd_port != 0); // the port should be defined in the config file

  /* Allocate main loop object */
  if (!(simple_poll = avahi_simple_poll_new())) {
    out_log(LEVEL_CRITICAL, "Failed to create simple poll object.\n");
    doderegistration();
  }

  poll_api = avahi_simple_poll_get(simple_poll);

  g_name = avahi_strdup(zeroconf_name);
  g_port = htonl(wzdftpd_port);

  /* Check wether creating the client object succeeded */
  if (!(client = avahi_client_new(poll_api, 0, client_callback, NULL, &error))) {
    out_log(LEVEL_CRITICAL, "Failed to create client: %s\n", avahi_strerror(error));
    doderegistration();
  }
#endif
#ifdef USE_HOWL
  if (sw_discovery_init(&discovery) != SW_OKAY)
  {
    out_log(LEVEL_CRITICAL, "sw_discovery_init() failed\n");
    return -1;
  }

  if ((result = sw_discovery_publish(discovery, 0, zeroconf_name, "_ftp._tcp.", NULL, NULL, htonl(wzdftpd_port), NULL, NULL, my_service_reply, NULL, &id)) != SW_OKAY)
  {
    out_log(LEVEL_CRITICAL, "publish failed: %d\n", result);
    sw_text_record_fina(text_record);
    return -1;
  }
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
    avahi_simple_poll_quit(simple_poll);
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

#ifdef USE_BONJOUR
/*
 * empty callback function for DNSServiceRegistrationCreate()
 */
static void
reg_reply(DNSServiceRegistrationReplyErrorType errorCode, void *context)
{
    (void) errorCode;
    (void) context;
}
#endif
#ifdef USE_AVAHI
static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata) {
    assert(g == group);

    /* Called whenever the entry group state changes */

    switch (state) {
      case AVAHI_ENTRY_GROUP_ESTABLISHED :
        /* The entry group has been established successfully */
        out_log(LEVEL_INFO, "Service '%s' successfully established.\n", g_name);
        break;

      case AVAHI_ENTRY_GROUP_COLLISION :
        {
          char *n;

          /* A service name collision happened. Let's pick a new name */
          n = avahi_alternative_service_name(g_name);
          avahi_free(g_name);
          g_name = n;

          out_log(LEVEL_HIGH, "Service name collision, renaming service to '%s'\n", g_name);

          /* And recreate the services */
          create_services(avahi_entry_group_get_client(g));
          break;
        }

      case AVAHI_ENTRY_GROUP_FAILURE :

        /* Some kind of failure happened while we were registering our services */
        avahi_simple_poll_quit(simple_poll);
        break;

      case AVAHI_ENTRY_GROUP_UNCOMMITED:
      case AVAHI_ENTRY_GROUP_REGISTERING:
        ;
    }
}

static void create_services(AvahiClient *c)
{
  int ret;
  assert(c);

  /* If this is the first time we're called, let's create a new entry group */
  if (!group)
    if (!(group = avahi_entry_group_new(c, entry_group_callback, NULL))) {
      out_log(LEVEL_CRITICAL, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
      goto fail;
    }

  out_log(LEVEL_INFO, "Adding Zeroconf service '%s'\n", g_name);

  /* Add the service for PostgreSQL */
  if ((ret = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, g_name, "_ftp._tcp", NULL, NULL, g_port, NULL, NULL)) < 0) {
    out_log(LEVEL_CRITICAL, "Failed to add _ftp._tcp service: %s\n", avahi_strerror(ret));
    goto fail;
  }

  /* Tell the server to register the service */
  if ((ret = avahi_entry_group_commit(group)) < 0) {
    out_log(LEVEL_CRITICAL, "Failed to commit entry_group: %s\n", avahi_strerror(ret));
    goto fail;
  }

  return;

fail:
  avahi_simple_poll_quit(simple_poll);
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void *userdata)
{
  assert(c);

  /* Called whenever the client or server state changes */

  switch (state) {
    case AVAHI_CLIENT_S_RUNNING:

      /* The server has startup successfully and registered its host
       * name on the network, so it's time to create our services */
      if (!group)
        create_services(c);
      break;

    case AVAHI_CLIENT_S_COLLISION:

      /* Let's drop our registered services. When the server is back
       * in AVAHI_SERVER_RUNNING state we will register them
       * again with the new host name. */
      if (group)
        avahi_entry_group_reset(group);
      break;

    case AVAHI_CLIENT_FAILURE:

      out_log(LEVEL_CRITICAL, "Client failure: %s\n", avahi_strerror(avahi_client_errno(c)));
      avahi_simple_poll_quit(simple_poll);

      break;

    case AVAHI_CLIENT_CONNECTING:
    case AVAHI_CLIENT_S_REGISTERING:
      ;
  }
}

static void doderegistration(void)
{
  /* Cleanup things */

  avahi_simple_poll_quit(simple_poll);
  if (client)
    avahi_client_free(client);

  if (simple_poll)
    avahi_simple_poll_free(simple_poll);

  if (g_name)
    avahi_free(g_name);

/*  if (group)
    avahi_entry_group_free(group);*/

  /* finally terminate the loop */
  avahi_simple_poll_quit(simple_poll);
}
#endif
#ifdef USE_HOWL
static sw_result HOWL_API my_service_reply(sw_discovery discovery,
                                           sw_discovery_oid oid,
                                           sw_discovery_publish_status status,
                                           sw_opaque extra)
{
  static sw_string
    status_text[] =
    {
      "Started",
      "Stopped",
      "Name Collision",
      "Invalid"
    };

  out_log(LEVEL_INFO, "publish reply: %s\n", status_text[status]);
  return SW_OKAY;
}
#endif

static void * routine (void * arg)
{
#ifdef USE_AVAHI
  int ret;

  /* this is a loop implementation ! */
  ret = avahi_simple_poll_loop(simple_poll);

  if (ret < 0) {
    out_log(LEVEL_CRITICAL, "Avahi poll thread quit with error: %s\n", avahi_strerror(ret));
  } else {
    out_log(LEVEL_NORMAL, "Avahi poll thread quit.\n");
  }

# ifndef ZEROCONF_USE_PROCESS
  /* clean things up */
  doderegistration();
# endif
#endif
#ifdef USE_HOWL
  /* this is a loop implementation ! */
  sw_discovery_run(discovery);
#endif

  out_log(LEVEL_FLOOD,"zeroconf: exit\n");

  return NULL;
}
