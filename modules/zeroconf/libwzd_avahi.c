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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef USE_AVAHI

#ifdef HAVE_PTHREAD
# include <pthread.h>
#endif

#include "libwzd_avahi.h"

static void publish_reply(AvahiEntryGroup *,
                          AvahiEntryGroupState,
                          void *);

/*
 * This function tries to register the FTP DNS
 * SRV service type.
 */
static void register_stuff(struct context *ctx) {
  char txt_uname[255], txt_pwd[255], txt_path[255];
  int txt_keys_size = 0;
  AvahiStringList* list = NULL;

  if (ctx->client) return;

  if (!ctx->group) {

    if (!(ctx->group = avahi_entry_group_new(ctx->client,
                                             publish_reply,
                                             ctx))) {
      out_log(LEVEL_CRITICAL,
              "Failed to create entry group: %s\n",
              avahi_strerror(avahi_client_errno(ctx->client)));
      goto fail;
    }

  }

  out_log(LEVEL_INFO, "Adding service '%s'\n", ctx->name);

  if (avahi_entry_group_is_empty(ctx->group)) {
    /* Register our service */

    /* prepare TXT records */
    if (ctx->username) {
      snprintf(txt_uname, 255, "u=%s", ctx->username);
      txt_keys_size++;

      out_log(LEVEL_INFO, "Adding TXT key '%s' to TXT array\n", txt_uname);
    }
    if (ctx->password) {
      snprintf(txt_pwd, 255, "p=%s", ctx->password);
      txt_keys_size++;

      out_log(LEVEL_INFO, "Adding TXT key '%s' to TXT array\n", txt_pwd);
    }
    if (ctx->path) {
      snprintf(txt_path, 255, "path=%s", ctx->path);
      txt_keys_size++;

      out_log(LEVEL_INFO, "Adding TXT key '%s' to TXT array\n", txt_path);
    }

    if (txt_keys_size > 0) {
      const char *txt_keys[txt_keys_size];
      int i = 0;

      out_log(LEVEL_INFO, "Adding %i TXT keys to list\n", txt_keys_size);

      while (i < txt_keys_size)
      {
        if (ctx->username)
        {
          txt_keys[i] = (const char*)&txt_uname;
          i++;
        }
        if (ctx->password)
        {
          txt_keys[i] = (const char*)&txt_pwd;
          i++;
        }
        if (ctx->path)
        {
          txt_keys[i] = (const char*)&txt_path;
          i++;
        }
      }

      list = avahi_string_list_new_from_array(txt_keys, txt_keys_size);

      if (avahi_entry_group_add_service_strlst(ctx->group,
                                               AVAHI_IF_UNSPEC,
                                               AVAHI_PROTO_UNSPEC,
                                               0,
                                               ctx->name,
                                               FTP_DNS_SERVICE_TYPE,
                                               NULL,
                                               NULL,
                                               ctx->port,
                                               list) < 0) {
        out_log(LEVEL_CRITICAL,
                "Failed to add service: %s\n",
                avahi_strerror(avahi_client_errno(ctx->client)));
        goto fail;
      }

      avahi_string_list_free(list);
    }
    else
    {
      if (avahi_entry_group_add_service(ctx->group,
                                        AVAHI_IF_UNSPEC,
                                        AVAHI_PROTO_UNSPEC,
                                        0,
                                        ctx->name,
                                        FTP_DNS_SERVICE_TYPE,
                                        NULL,
                                        NULL,
                                        ctx->port,
                                        NULL) < 0) {
        out_log(LEVEL_CRITICAL,
                "Failed to add service: %s\n",
                avahi_strerror(avahi_client_errno(ctx->client)));
        goto fail;
      }
    }

    if (avahi_entry_group_commit(ctx->group) < 0) {
      out_log(LEVEL_CRITICAL,
              "Failed to commit entry group: %s\n",
              avahi_strerror(avahi_client_errno(ctx->client)));
      goto fail;
    }
  }

  return;

  fail:
    avahi_client_free (ctx->client);
#ifndef HAVE_AVAHI_THREADED_POLL
    avahi_simple_poll_quit(ctx->simple_poll);
#else
    avahi_threaded_poll_quit(ctx->threaded_poll);
#endif
}

/* Called when publishing of service data completes */
static void publish_reply(AvahiEntryGroup *g,
                          AvahiEntryGroupState state,
                          AVAHI_GCC_UNUSED void *userdata)
{
  struct context *ctx = userdata;


  switch (state) {

  case AVAHI_ENTRY_GROUP_ESTABLISHED :
    /* The entry group has been established successfully */
    break;

  case AVAHI_ENTRY_GROUP_COLLISION: {
    char *n;

    /* Pick a new name for our service */

    n = avahi_alternative_service_name(ctx->name);
    if (!n) break;

    avahi_free(ctx->name);
    ctx->name = n;

    register_stuff(ctx);
    break;
  }

  case AVAHI_ENTRY_GROUP_FAILURE: {
    out_log(LEVEL_CRITICAL,
            "Failed to register service: %s\n",
            avahi_strerror(avahi_client_errno(ctx->client)));
    avahi_client_free (avahi_entry_group_get_client(g));
#ifndef HAVE_AVAHI_THREADED_POLL
    avahi_simple_poll_quit(ctx->simple_poll);
#else
    avahi_threaded_poll_quit(ctx->threaded_poll);
#endif
    break;
  }

  case AVAHI_ENTRY_GROUP_UNCOMMITED:
  case AVAHI_ENTRY_GROUP_REGISTERING:
    ;
  }
}

static void client_callback(AvahiClient *client,
                            AvahiClientState state,
                            void *userdata)
{
  struct context *ctx = userdata;

  ctx->client = client;

  switch (state) {

  case AVAHI_CLIENT_S_RUNNING:

    /* The server has startup successfully and registered its host
     * name on the network, so it's time to create our services */
    if (!ctx->group)
      register_stuff(ctx);
    break;

  case AVAHI_CLIENT_S_COLLISION:

    if (ctx->group)
      avahi_entry_group_reset(ctx->group);
    break;

  case AVAHI_CLIENT_FAILURE: {

    if (avahi_client_errno(client) == AVAHI_ERR_DISCONNECTED) {
      int error;

      avahi_client_free(ctx->client);
      ctx->client = NULL;
      ctx->group = NULL;

      /* Reconnect to the server */

#ifndef HAVE_AVAHI_THREADED_POLL
      if (!(ctx->client = avahi_client_new(avahi_simple_poll_get(ctx->simple_poll),
#else
      if (!(ctx->client = avahi_client_new(avahi_threaded_poll_get(ctx->threaded_poll),
#endif
                                           AVAHI_CLIENT_NO_FAIL,
                                           client_callback,
                                           ctx,
                                           &error))) {

        out_log(LEVEL_CRITICAL, "Failed to contact server: %s\n", avahi_strerror(error));

        avahi_client_free (ctx->client);
#ifndef HAVE_AVAHI_THREADED_POLL
        avahi_simple_poll_quit(ctx->simple_poll);
#else
        avahi_threaded_poll_quit(ctx->threaded_poll);
#endif
      }

      } else {
        out_log(LEVEL_CRITICAL, "Client failure: %s\n", avahi_strerror(avahi_client_errno(client)));

        avahi_client_free (ctx->client);
#ifndef HAVE_AVAHI_THREADED_POLL
        avahi_simple_poll_quit(ctx->simple_poll);
#else
        avahi_threaded_poll_quit(ctx->threaded_poll);
#endif
      }

    break;
  }

  case AVAHI_CLIENT_S_REGISTERING:
  case AVAHI_CLIENT_CONNECTING:
    ;
  }
}

static void* thread(void *userdata) {
#ifndef HAVE_AVAHI_THREADED_POLL
  struct context *ctx = userdata;
  sigset_t mask;
  int r;

  /* Make sure that signals are delivered to the main thread */
  sigfillset(&mask);
  pthread_sigmask(SIG_BLOCK, &mask, NULL);

  pthread_mutex_lock(&ctx->mutex);

  /* Run the main loop */
  r = avahi_simple_poll_loop(ctx->simple_poll);

  /* Cleanup some stuff */
  if (ctx->client)
    avahi_client_free(ctx->client);
  ctx->client = NULL;
  ctx->group = NULL;
    
  pthread_mutex_unlock(&ctx->mutex);
#endif    
  return NULL;
}

static int poll_func(struct pollfd *ufds,
                     unsigned int nfds,
                     int timeout,
                     void *userdata) {
#ifndef HAVE_AVAHI_THREADED_POLL
  pthread_mutex_t *mutex = userdata;
  int r;

  /* Before entering poll() we unlock the mutex, so that
   * avahi_simple_poll_quit() can succeed from another thread. */

  pthread_mutex_unlock(mutex);
  r = poll(ufds, nfds, timeout);
  pthread_mutex_lock(mutex);

  return r;
#else
  return 0;
#endif
}

/*
 * Tries to setup the Zeroconf thread and any
 * neccessary config setting.
 */
void* av_zeroconf_setup(unsigned long port,
                        const char *name,
                        const char *username,
                        const char *password,
                        const char *path) {
  struct context *ctx = NULL;

  /* default service name, if there's none in
   * the config file.
   */
  char service[256] = "WZDFTP Server on ";
  int error;

  /* initialize the struct that holds our
   * config settings.
   */
  ctx = malloc(sizeof(struct context));
  if (ctx == NULL) return NULL;
  ctx->client = NULL;
  ctx->group = NULL;
#ifndef HAVE_AVAHI_THREADED_POLL
  ctx->simple_poll = NULL;
#else
  ctx->threaded_poll = NULL;
#endif
  ctx->thread_running = 0;
  ctx->port = port;
  pthread_mutex_init(&ctx->mutex, NULL);

  /* Prepare service name */
  if (!name) {
    out_log(LEVEL_INFO, "Assigning default service name.\n");
    gethostname(service+17, sizeof(service)-18);
    service[sizeof(service)-1] = 0;

    ctx->name = strdup(service);
  }
  else {
    ctx->name = strdup(name);
  }

  /* assign TXT keys if any */
  if (username) {
    ctx->username = strdup(username);
  }
  else {
    ctx->username = NULL;
  }
  if (password) {
    ctx->password = strdup(password);
  }
  else {
    ctx->password = NULL;
  }
  if (path) {
    ctx->path = strdup(path);
  }
  else {
    ctx->path = NULL;
  }

  if (strlen(ctx->name) <= 0) return NULL;

/* first of all we need to initialize our threading env */
#ifdef HAVE_AVAHI_THREADED_POLL
  if (!(ctx->threaded_poll = avahi_threaded_poll_new())) {
     return NULL;
  }
#else
  if (!(ctx->simple_poll = avahi_simple_poll_new())) {
      out_log(LEVEL_CRITICAL, "Failed to create event loop object.\n");
      goto fail;
  }

  avahi_simple_poll_set_func(ctx->simple_poll, poll_func, &ctx->mutex);
#endif

/* now we need to acquire a client */
#ifdef HAVE_AVAHI_THREADED_POLL
  if (!(ctx->client = avahi_client_new(avahi_threaded_poll_get(ctx->threaded_poll),
                                       AVAHI_CLIENT_NO_FAIL,
                                       client_callback,
                                       ctx,
                                       &error))) {
    out_log(LEVEL_CRITICAL,
            "Failed to create client object: %s\n",
            avahi_strerror(avahi_client_errno(ctx->client)));
    goto fail;
  }
#else
  if (!(ctx->client = avahi_client_new(avahi_simple_poll_get(ctx->simple_poll),
                                       AVAHI_CLIENT_NO_FAIL,
                                       client_callback,
                                       ctx,
                                       &error))) {
    out_log(LEVEL_CRITICAL,
            "Failed to create client object: %s\n",
            avahi_strerror(avahi_client_errno(ctx->client)));
    goto fail;
  }
#endif

  return ctx;

fail:

  if (ctx)
    av_zeroconf_unregister(ctx);

  return NULL;
}

/*
 * This function finally runs the loop impl.
 */
int av_zeroconf_run(void *u) {
  struct context *ctx = u;
#ifndef HAVE_AVAHI_THREADED_POLL
  int ret;
#endif

#ifdef HAVE_AVAHI_THREADED_POLL
  /* Finally, start the event loop thread */
  if (avahi_threaded_poll_start(ctx->threaded_poll) < 0) {
    out_log(LEVEL_CRITICAL,
            "Failed to create thread: %s\n",
            avahi_strerror(avahi_client_errno(ctx->client)));
    goto fail;
  } else {
    out_log(LEVEL_INFO, "Successfully started avahi loop.\n");
  }
#else
  /* Create the mDNS event handler */
  if ((ret = pthread_create(&ctx->thread_id, NULL, thread, ctx)) < 0) {
    out_log(LEVEL_CRITICAL, "Failed to create thread: %s\n", strerror(ret));
    goto fail;
  } else {
    out_log(LEVEL_INFO, "Successfully started avahi loop.\n");
  }
#endif

  ctx->thread_running = 1;

  return 0;

fail:

  if (ctx)
    av_zeroconf_unregister(ctx);

  return -1;
}

/*
 * Used to lock access to the loop.
 * Currently unused.
 */
void av_zeroconf_lock(void *u) {
#ifdef HAVE_AVAHI_THREADED_POLL
  struct context *ctx = u;

  avahi_threaded_poll_lock(ctx->threaded_poll);
#endif
}

/*
 * Used to unlock access to the loop.
 * Currently unused.
 */
void av_zeroconf_unlock(void *u) {
#ifdef HAVE_AVAHI_THREADED_POLL
  struct context *ctx = u;

  avahi_threaded_poll_unlock(ctx->threaded_poll);
#endif
}

/*
 * Tries to shutdown this loop impl.
 * Call this function from outside this thread.
 */
void av_zeroconf_shutdown(void *u) {
  struct context *ctx = u;

  out_log(LEVEL_INFO, "Going to free Avahi-related ressources...\n");

  /* Call this when the app shuts down */
#ifdef HAVE_AVAHI_THREADED_POLL
  if (ctx->threaded_poll)
    avahi_threaded_poll_stop(ctx->threaded_poll);
  if (ctx->name)
    avahi_free(ctx->name);
  if (ctx->client)
    avahi_client_free(ctx->client);
  if (ctx->threaded_poll)
    avahi_threaded_poll_free(ctx->threaded_poll);
#else
  av_zeroconf_unregister(ctx);
#endif

  out_log(LEVEL_INFO, "Finished freeing Avahi-related ressources.\n");
}

/*
 * Tries to shutdown this loop impl.
 * Call this function from inside this thread.
 */
int av_zeroconf_unregister(void *u) {
  struct context *ctx = u;

  if (ctx->thread_running) {
#ifndef HAVE_AVAHI_THREADED_POLL
    pthread_mutex_lock(&ctx->mutex);
    avahi_simple_poll_quit(ctx->simple_poll);
    pthread_mutex_unlock(&ctx->mutex);

    pthread_join(ctx->thread_id, NULL);
#else
    /* First, block the event loop */
    avahi_threaded_poll_lock(ctx->threaded_poll);

    /* Than, do your stuff */
    avahi_threaded_poll_quit(ctx->threaded_poll);

    /* Finally, unblock the event loop */
    avahi_threaded_poll_unlock(ctx->threaded_poll);
#endif
    ctx->thread_running = 0;
  }

  avahi_free(ctx->name);

  if (ctx->client)
    avahi_client_free(ctx->client);

#ifndef HAVE_AVAHI_THREADED_POLL
  if (ctx->simple_poll)
    avahi_simple_poll_free(ctx->simple_poll);

  pthread_mutex_destroy(&ctx->mutex);
#else
  if (ctx->threaded_poll)
    avahi_threaded_poll_free(ctx->threaded_poll);
#endif

  free(ctx);

  return 0;
}

#endif /* USE_AVAHI */

