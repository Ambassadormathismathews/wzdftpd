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
/*! \addtogroup wzdftpd
 *  @{
 */


#if defined(WIN32)
#include <winsock2.h>
#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

/** \todo XXX FIXME remove this line and use correct types !!!!
 * this is used to convert char* to struct in6_addr
 */
#define PORCUS_CAST(x) ( ((struct in6_addr*)(x)) )

#endif /* WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* isspace */
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#ifndef WIN32
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <regex.h>
#include <dlfcn.h>
#include <pthread.h>
#include <syslog.h>
#else
#include <io.h>
#include <process.h> /* _getpid() */
#endif

#if defined(WIN32) || defined(__sun__)
/* cygwin does not support ipv6 */
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#endif

#include <libwzd-core/wzd_structs.h>

#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_tls.h>
#include <libwzd-core/wzd_fs.h>
#include <libwzd-core/wzd_ip.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_ClientThread.h>
#include <libwzd-core/wzd_vfs.h>
#include <libwzd-core/wzd_perm.h>
#include <libwzd-core/wzd_socket.h>
#include <libwzd-core/wzd_mod.h>
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_configloader.h>
#include <libwzd-core/wzd_crontab.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_section.h>
#include <libwzd-core/wzd_site.h>
#include <libwzd-core/wzd_threads.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_utf8.h>
#include <libwzd-core/wzd_vars.h>

#include "wzd_ServerThread.h"

#include <libwzd-core/wzd_debug.h>

/************ PROTOTYPES ***********/
void serverMainThreadProc(void *arg);
void serverMainThreadExit(int);
void server_crashed(int signum);

void child_interrupt(int signum);
void reset_stats(wzd_server_stat_t * stats);

int check_server_dynamic_ip(void);
int commit_backend(void);
void server_rebind(const char *new_ip, unsigned int new_port);

int server_switch_to_config(wzd_config_t *config);

typedef struct {
  fd_t read_fd;
  fd_t write_fd;
  wzd_context_t * context;
} wzd_ident_context_t;

typedef struct {
  unsigned short dynamic;
  char *         ip;
  fd_t           sock;
} server_ip_t;

/************ PUBLIC **************/
int runMainThread(int argc, char **argv)
{
  const char * build_version = WZD_VERSION_STR;

  out_log(LEVEL_FLOOD,"DEBUG Checking library version\n");

  /* check that library was compiled in the same version as executable
   *
   * we are trying to avoid the dll hell, especially on windows
   */
  if (strcmp(build_version,wzd_get_version_long()) != 0) {
    out_log(LEVEL_CRITICAL,"FATAL wzdftpd was NOT compiled for this library version\n");
    out_log(LEVEL_CRITICAL,"FATAL   wzdftpd:     [%s]\n",WZD_VERSION_STR);
    out_log(LEVEL_CRITICAL,"FATAL   libwzd-core: [%s]\n",wzd_get_version_long());

    exit (-1);
  }

  serverMainThreadProc(0);

  return 0;
}

/************ PRIVATE *************/

static wzd_mutex_t * end_mutex = NULL;

static void free_config(wzd_config_t * config);

static List server_ip_list;
static List server_ident_list;
static int server_add_ident_candidate(fd_t socket_accept_fd);
static void server_ident_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd);
static void server_ident_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds);
static void server_ident_remove(wzd_ident_context_t * ident_context);
static void server_ident_timeout_check(void);

static void server_control_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd);;
static void server_control_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds);

static void server_login_accept(wzd_context_t * context);

static void server_ip_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds);
static void server_ip_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd);
static void server_ip_free(void * p);

static int check_ip_before_login(wzd_context_t * context);


static void context_init(wzd_context_t * context)
{
  memset(context,0,sizeof(wzd_context_t));
  context->controlfd = -1;
  context->datafd = -1;
  context->pasvsock = -1;
  context->userid = (unsigned int)-1;
  context->thread_id = (unsigned long)-1;
  context->state = STATE_UNKNOWN;
  context->datamode = DATA_PORT;
  context->current_action.current_file = -1;
  context->current_action.token = TOK_UNKNOWN;
  memset(&context->last_file,0,sizeof(context->last_file));

  context->peer_ip = ip_create();

  context->tls_role = TLS_SERVER_MODE;
  context->read_fct = (read_fct_t)clear_read;
  context->write_fct = (write_fct_t)clear_write;
}

static wzd_context_t * context_find_free(List * context_list)
{
  wzd_context_t * context=NULL;

  wzd_mutex_lock(server_mutex);
  context = wzd_malloc(sizeof(wzd_context_t));
  context_init(context);
  if (list_ins_next(context_list, NULL, context))
  {
    wzd_free(context);
    context = NULL;
  }
  else {
    context->magic = CONTEXT_MAGIC; /* set magic number inside lock ! */
  }
  wzd_mutex_unlock(server_mutex);

  return context;
}

static void server_ip_free(void * p)
{
  server_ip_t * s = p;
  if (s->sock >= 0) {
    /** \todo shutdown SSL ? */
    socket_close(s->sock);
    FD_UNREGISTER(s->sock,"Server listening socket");
  }
  wzd_free( s->ip );
  memset(s, 0, sizeof(*s));
  wzd_free( s );
}

void reset_stats(wzd_server_stat_t * stats)
{
  stats->num_connections = 0;
  stats->num_childs = 0;
}

/** \return 1 if ip is ok, 0 if ip is denied, -1 if ip is not in list or on error */
static int global_check_ip_allowed(unsigned char *userip)
{
  char ip[INET6_ADDRSTRLEN];

  /** \warning If no ip was specified (ok or denied), then the default is to allow */
  if (mainConfig->login_pre_ip_checks == NULL) return 1;

#if !defined(IPV6_SUPPORT)
  inet_ntop(AF_INET,userip,ip,INET_ADDRSTRLEN);
#else
  inet_ntop(AF_INET6,userip,ip,INET6_ADDRSTRLEN);
#endif

  return ip_list_check(mainConfig->login_pre_ip_checks,ip);
}

void server_rebind(const char *new_ip, unsigned int new_port)
{
  out_log(LEVEL_HIGH,"ERROR server_rebind: not implemented yet\n");
#if 0
  fd_t sock;
  const char *ip = (new_ip) ? new_ip : mainConfig->ip;

  /* create socket iff different ports ?! */
  sock = mainConfig->mainSocket;
  socket_close(sock);

  sock = mainConfig->mainSocket = socket_make((const char *)ip,&new_port,mainConfig->max_threads,WZD_INET_NONE);
  if (sock == (fd_t)-1) {
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
#endif
}

/* checks if dynamic ip has changed, and rebind main socket if true
 */
int check_server_dynamic_ip(void)
{
  if (CFG_GET_OPTION(mainConfig,CFG_OPT_DYNAMIC_IP)) {
    out_log(LEVEL_FLOOD,"DEBUG check_server_dynamic_ip: not implemented yet\n");

    /* get ip and port */

    /* update pasv_ip */

    /* rebind server if needed */

    return -1;
  }

  return 0;
#if 0
  struct sockaddr_in sa_current, sa_config;
  unsigned int size;
  const unsigned char * str_ip_current;
  const unsigned char * str_ip_config;
  const unsigned char * str_ip_pasv;

/*out_err(LEVEL_CRITICAL,"check_server_dynamic_ip\n");*/
  if (!mainConfig->dynamic_ip || strlen((const char *)mainConfig->dynamic_ip)<=0) return 0;

  if (strcmp((const char *)mainConfig->dynamic_ip,"0")==0) return 0;

  /* 1- get my ip */
  size = sizeof(struct sockaddr_in);
  /* XXX The socket is NOT connected, so getsockname will ALWAYS return -1
  */
  getsockname(mainConfig->mainSocket,(struct sockaddr *)&sa_current,&size);
/*  {
    unsigned char *myip = (unsigned char*)&sa_current.sin_addr;
    out_err(LEVEL_CRITICAL,"IP: %d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
  }*/

  /* get ip by system */
  if (strcmp((const char *)mainConfig->dynamic_ip,"1")==0)
  {
    struct in_addr addr_current;
    int ret;
    ret = get_system_ip("eth0",&addr_current);
    if (ret < 0) {
      out_err(LEVEL_HIGH,"get_system_ip FAILED %s:%d\n",
          __FILE__,__LINE__);
      return -1;
    }
/*    out_log(LEVEL_CRITICAL,"SYSTEM IP: %s\n",inet_ntoa(addr_current));*/
    sa_config.sin_addr.s_addr = addr_current.s_addr;
  }

/*  if (mainConfig->dynamic_ip[0]=='+')*/ /** \todo remove me if it works */
  {
    const char *ip = (const char *)mainConfig->dynamic_ip;

   /* 2- resolve config ip */
    if (strcmp(ip,"*")==0)
      sa_config.sin_addr.s_addr = htonl(INADDR_ANY);
    else
    {
      struct hostent* host_info;
      // try to decode dotted quad notation
#if defined(WIN32) || defined(__sun__)
      if ((sa_config.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
#else
      if(!inet_aton(ip, &sa_config.sin_addr))
#endif
      {
        // failing that, look up the name
        if( (host_info = gethostbyname(ip)) == NULL)
        {
          out_err(LEVEL_CRITICAL,"Could not resolve ip %s %s:%d\n",ip,__FILE__,__LINE__);
          return -1;
        }
        memcpy(&sa_config.sin_addr, host_info->h_addr, host_info->h_length);
      }
    }
/*    {
      unsigned char *myip = (unsigned char*)&sa_config.sin_addr;
      out_err(LEVEL_CRITICAL,"RESOLVED IP: %d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
    }*/
  } /* if (mainConfig->dynamic_ip[0]=='+') */

  str_ip_current = (const unsigned char*)&sa_current.sin_addr.s_addr;
  str_ip_config = (const unsigned char*)&sa_config.sin_addr.s_addr;
  str_ip_pasv = (const unsigned char*)mainConfig->pasv_ip;

  /* if different, rebind */ /* XXX FIXME what to do with old connections ? */
  {
    if (sa_current.sin_addr.s_addr != 0 && (sa_current.sin_addr.s_addr != sa_config.sin_addr.s_addr) ) {
      out_log(LEVEL_HIGH,"Rebinding main server ! (from %hhu.%hhu.%hhu.%hhu to %hhu.%hhu.%hhu.%hhu)\n",
          str_ip_current[0],str_ip_current[1],str_ip_current[2],str_ip_current[3],
          str_ip_config[0],str_ip_config[1],str_ip_config[2],str_ip_config[3]);
      server_rebind(inet_ntoa(sa_config.sin_addr),mainConfig->port);
    }
  }

  /* anyway, I need to rebind pasv ip ?! */
  {
    if ( str_ip_pasv[0] != '0' && (
          str_ip_config[0] != str_ip_pasv[0]
          || str_ip_config[1] != str_ip_pasv[1]
          || str_ip_config[2] != str_ip_pasv[2]
          || str_ip_config[3] != str_ip_pasv[3] ) )
    {
      out_log(LEVEL_HIGH,"Changing PASV ip !\n");
      mainConfig->pasv_ip[0] = str_ip_config[0];
      mainConfig->pasv_ip[1] = str_ip_config[1];
      mainConfig->pasv_ip[2] = str_ip_config[2];
      mainConfig->pasv_ip[3] = str_ip_config[3];
    }
  }
  return 0;
#endif /* 0 */
}


int commit_backend(void)
{
  /* TODO XXX FIXME flush backend IFF modified ! */
  if (!mainConfig) return 1;
  backend_commit_changes(mainConfig->backends->filename);
  return 0;
}

static int check_ip_before_login(wzd_context_t * context)
{
  char inet_buf[INET6_ADDRSTRLEN]; /* usually 46 */
  unsigned char * userip;
  wzd_group_t * loop_group;
  wzd_user_t * loop_user;
  gid_t * gid_list;
  uid_t * uid_list;
  int i, ret;

  userip = context->hostip;
#if defined(IPV6_SUPPORT)
  if (context->family == WZD_INET6) {
    inet_ntop(AF_INET6,userip,inet_buf,INET6_ADDRSTRLEN);
  } else
#endif
  {
    inet_ntop(AF_INET,userip,inet_buf,INET_ADDRSTRLEN);
  }

  /* check for all groups */
  gid_list = (gid_t*)backend_get_group(GET_GROUP_LIST);
  if (gid_list) {
    for (i=0; gid_list[i] != (gid_t)-1; i++) {
      loop_group = GetGroupByID(gid_list[i]);
      if (loop_group) {
        ret = ip_list_check_ident(loop_group->ip_list, inet_buf, context->ident);
        if (ret > 1) return 0; /* found ! */
      }
    }
    wzd_free(gid_list);
  }

  /* check for all users */
  uid_list = (uid_t*)backend_get_user(GET_USER_LIST);
  if (uid_list) {
    for (i=0; uid_list[i] != (uid_t)-1; i++) {
      loop_user = GetUserByID(uid_list[i]);
      if (loop_user) {
        ret = ip_list_check_ident(loop_user->ip_list, inet_buf, context->ident);
        if (ret) return 0; /* found ! */
      }
    }
    wzd_free(uid_list);
  }


  return 1;
}

/*
 * add idents to the correct fd_set
 */
static void server_control_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd)
{
  if (mainConfig->controlfd != (fd_t)-1) {
    FD_SET(mainConfig->controlfd,r_fds);
    FD_SET(mainConfig->controlfd,e_fds);
    *maxfd = MAX(*maxfd,mainConfig->controlfd);
  }
}

static void server_control_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds)
{
  if (mainConfig->controlfd != (fd_t)-1) {
    if (FD_ISSET(mainConfig->controlfd,e_fds)) { /* error */
      /** \todo XXX FIXME error on control FD, warn user, and then ? */
      out_log(LEVEL_HIGH, "Error on control fd: %d %s\n",errno,strerror(errno));
      return;
    }
    if (FD_ISSET(mainConfig->controlfd,r_fds)) { /* get control entry */
      /** \todo XXX FIXME spawn a new control thread: authenticate user then take commands */
    }
  }
}

/*
 * add a connection to the list of idents to be checked
 */
static int server_add_ident_candidate(fd_t socket_accept_fd)
{
  unsigned char remote_host[16];
  unsigned int remote_port;
  char inet_buf[INET6_ADDRSTRLEN]; /* usually 46 */
  unsigned char userip[16];
  fd_t newsock, fd_ident;
  unsigned short ident_port = 113;
  wzd_context_t * context;
  wzd_ident_context_t * ident_context;
  net_family_t family;

  newsock = socket_accept(socket_accept_fd, remote_host, &remote_port, &family);
  if (newsock == (fd_t)-1)
  {
    out_log(LEVEL_HIGH,"Error while accepting\n");
    serverMainThreadExit(-1); /** \todo do not exit server, just client */
  }
  FD_REGISTER(newsock,"Client control socket");

  memcpy(userip,remote_host,16);

#if defined(IPV6_SUPPORT)
  if (family == WZD_INET6) {
    inet_ntop(AF_INET6,userip,inet_buf,INET6_ADDRSTRLEN);
    if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(userip)))
      out_log(LEVEL_INFO,"IP is IPv4 compatible\n");
  } else
#endif
  {
    inet_ntop(AF_INET,userip,inet_buf,INET_ADDRSTRLEN);
  }

  /* Here we check IP BEFORE starting session */
  if (global_check_ip_allowed(userip)<=0) { /* IP was rejected */
    /* close socket without warning ! */
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    out_log(LEVEL_HIGH,"Failed login from %s: global ip rejected\n",
      inet_buf);
    return 1;
  }

  if (mainConfig->max_threads > 0 &&
      list_size(context_list) >= mainConfig->max_threads) { /* too many connections */
    /* XXX FIXME close socket without warning ! */
    clear_write(newsock, "421 Too many connections\r\n", 25, 0, 2, NULL);
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    out_log(LEVEL_INFO,"Failed login from %s: too many connections\n",
      inet_buf);
    return 2;
  }

  out_log(LEVEL_NORMAL,"Connection opened from %s (socket %d)\n", inet_buf,newsock);

  /* 1. create new context */
  context = context_find_free(context_list);
  if (!context) {
    out_log(LEVEL_CRITICAL,"Could not get a free context - hard user limit reached ?\n");
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    return 3;
  }

  /* don't forget init is done before */
/*  context->magic = CONTEXT_MAGIC;*/  /* magic is set inside lock, it makes no sense here */
  context->state = STATE_CONNECTING;
  context->controlfd = newsock;
  context->family = family;
  time (&context->login_time);

  memcpy(context->hostip,userip,sizeof(context->hostip));

  /* check if ident lookups are disabled */
  if (CFG_GET_OPTION(mainConfig,CFG_OPT_DISABLE_IDENT)) {
    server_login_accept(context);
    return 0;
  }

  /* try to open ident connection, the same type as the incoming connection */
  fd_ident = socket_connect(userip,family,ident_port,0,newsock,HARD_IDENT_TIMEOUT);

  if (fd_ident == (fd_t)-1) {
    if (errno == ENOTCONN || errno == ECONNREFUSED || errno == ETIMEDOUT) {
      server_login_accept(context);
      return 0;
    }
#ifdef WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
      server_login_accept(context);
      return 0;
    }
#endif
    out_log(LEVEL_INFO,"Could not get ident (error: %d %s)\n",errno,strerror(errno));
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    return 4;
  }
  FD_REGISTER(fd_ident,"Ident socket"); /** \todo add more info to description: client number, etc */

  /* add connection to ident list */
  ident_context = malloc(sizeof(wzd_ident_context_t));
  ident_context->read_fd = -1;
  ident_context->write_fd = fd_ident;
  ident_context->context = context;
  if (list_ins_next(&server_ident_list, NULL, ident_context)) {
    free(ident_context);
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    return 5;
  }

  return 0;
}

/*
 * add idents to the correct fd_set
 */
static void server_ident_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd)
{
  ListElmt * elmnt;
  wzd_ident_context_t * ident_context;

  for (elmnt=server_ident_list.head; elmnt; elmnt=list_next(elmnt)) {
    ident_context = list_data(elmnt);
    if (!ident_context) continue;
    if (ident_context->read_fd != (fd_t)-1)
    {
      FD_SET(ident_context->read_fd,r_fds);
      FD_SET(ident_context->read_fd,e_fds);
      *maxfd = MAX(*maxfd,ident_context->read_fd);
    }
    if (ident_context->write_fd != (fd_t)-1)
    {
      FD_SET(ident_context->write_fd,w_fds);
      FD_SET(ident_context->write_fd,e_fds);
      *maxfd = MAX(*maxfd,ident_context->write_fd);
    }
  }
}

/*
 * add a connection to the list of idents to be checked
 */
static void server_ident_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds)
{
  char buffer[1024];
  const char * ptr;
  wzd_context_t * context=NULL;
  unsigned short remote_port;
  unsigned short local_port;
  fd_t fd_ident;
  int ret;
  ListElmt * elmnt;
  wzd_ident_context_t * ident_context;

  if (!server_ident_list.head) return;

  for (elmnt=server_ident_list.head; elmnt; elmnt=list_next(elmnt)) {
    ident_context = list_data(elmnt);
    if (!ident_context) continue;

    context = ident_context->context;

    if (ident_context->read_fd != (fd_t)-1)
    {
      if (FD_ISSET(ident_context->read_fd,e_fds)) { /* error */
        /* remove ident connection from list and continues with no ident */
        out_log(LEVEL_INFO,"error reading ident response %d %s\n",errno,strerror(errno));
        FD_UNREGISTER(fd_ident,"Ident socket");
        socket_close(fd_ident);
        goto continue_connection;
      } else
      if (FD_ISSET(ident_context->read_fd,r_fds)) { /* get ident */
        fd_ident = ident_context->read_fd;
        context = ident_context->context;

        /* 4- try to read response */
        ret = recv(fd_ident,buffer,sizeof(buffer),0);
        if (ret < 0) {
#ifdef _MSC_VER
          errno = WSAGetLastError();
          FD_UNREGISTER(fd_ident,"Ident socket");
          socket_close(fd_ident);
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
#endif
          if (errno == EINPROGRESS) continue;
          out_log(LEVEL_INFO,"error reading ident request %s\n",strerror(errno));
          FD_UNREGISTER(fd_ident,"Ident socket");
          socket_close(fd_ident);
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
        }
        buffer[ret] = '\0';

        socket_close(fd_ident);
        FD_UNREGISTER(fd_ident,"Ident socket");

        /* 5- decode response */
        ptr = strrchr(buffer,':');
        if (!ptr) {
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
        }
        ptr++; /* skip ':' */
        while (*ptr && isspace(*ptr)) ptr++;
        context->ident = wzd_strdup(ptr);
        chop(context->ident);

#ifdef WZD_DBG_IDENT
        out_log(LEVEL_NORMAL,"received ident %s\n",context->ident);
#endif

continue_connection:
        /* remove ident from list and accept login */
        server_ident_remove(ident_context);
        elmnt = server_ident_list.head;

        server_login_accept(context);

        if (!elmnt) return;
      }
    }
    else if (ident_context->write_fd != (fd_t)-1)
    {
      fd_ident = ident_context->write_fd;
      if (FD_ISSET(ident_context->write_fd,e_fds)) { /* error */
        /* remove ident connection from list and continues with no ident */
        out_log(LEVEL_INFO,"error sending ident request %d %s\n",errno,strerror(errno));
        FD_UNREGISTER(fd_ident,"Ident socket");
        socket_close(fd_ident);
        goto continue_connection;
        ret = 0;
      }
      if (FD_ISSET(ident_context->write_fd,w_fds)) { /* write ident request */
        context = ident_context->context;

        /* 2- get local and remote ports */

        /* get remote port number */
        local_port = socket_get_local_port(context->controlfd);
        remote_port = socket_get_remote_port(context->controlfd);

        snprintf(buffer,sizeof(buffer),"%u, %u\r\n",remote_port,local_port);

        /* 3- try to write */
        ret = send(fd_ident,buffer,strlen(buffer),0);
        if (ret < 0) {
#ifdef _MSC_VER
          errno = WSAGetLastError();
          FD_UNREGISTER(fd_ident,"Ident socket");
          socket_close(fd_ident);
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
#endif
          if (errno == EINPROGRESS) continue;
          out_log(LEVEL_INFO,"error sending ident request %s\n",strerror(errno));
          socket_close(fd_ident);
          FD_UNREGISTER(fd_ident,"Ident socket");
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
        }
        /* now we wait ident answer */
        ident_context->read_fd = fd_ident;
        ident_context->write_fd = -1;
      }
    }
  }
}

/*
 * removes ident from list by replacing this entry by the last
 */
static void server_ident_remove(wzd_ident_context_t * ident_context)
{
  ListElmt * elmnt;
  void * data;

  if (!server_ident_list.head) return;

  if (ident_context == server_ident_list.head->data)
  {
    list_rem_next(&server_ident_list, NULL, &data);
    free(ident_context);
    return;
  }

  for (elmnt=server_ident_list.head; elmnt; elmnt=list_next(elmnt))
  {
    if ( list_next(elmnt) && ident_context == list_next(elmnt)->data )
    {
      list_rem_next(&server_ident_list, elmnt, &data);
      free(ident_context);
      return;
    }
  }

  /* we should never be here ! */

#ifdef DEBUG
  server_crashed(-1);
#endif
}

static void server_ip_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds)
{
  int ret;
  ListElmt * elmnt;
  server_ip_t * server_ip;

  if (!server_ip_list.head) return;

  for (elmnt=server_ip_list.head; elmnt; elmnt=list_next(elmnt)) {
    server_ip = list_data(elmnt);
    if (!server_ip) continue;

    if (server_ip->sock != (fd_t)-1)
    {
      if (FD_ISSET(server_ip->sock,e_fds)) { /* error */
        out_log(LEVEL_INFO,"ERROR reading response (%d) %d %s\n",server_ip->sock,errno,strerror(errno));
      } else
      if (FD_ISSET(server_ip->sock,r_fds)) { /* get ident */
        if ((ret=server_add_ident_candidate(server_ip->sock))) {
          if (ret != 1 /* global ip rejected */ &&
              ret != 2 /* too many connections */
             )
            out_log(LEVEL_NORMAL,"could not add ident candidate for connection: %d (errno: %d: %s) :%s:%d\n",
                ret, errno, strerror(errno), __FILE__, __LINE__);
          continue; /* possible cause of error: global ip rejected */
/*          serverMainThreadExit(-1);*/
          /* we abort, so we never returns */
        }
        mainConfig->stats.num_connections++;
      }
    }
  }
}

/*
 * add server ips to the correct fd_set
 */
static void server_ip_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, fd_t * maxfd)
{
  ListElmt * elmnt;
  server_ip_t * server_ip;

  for (elmnt=server_ip_list.head; elmnt; elmnt=list_next(elmnt)) {
    server_ip = list_data(elmnt);
    if (!server_ip) continue;
    if (server_ip->sock != (fd_t)-1)
    {
      FD_SET(server_ip->sock,r_fds);
      FD_SET(server_ip->sock,e_fds);
      *maxfd = MAX(*maxfd,server_ip->sock);
    }
  }
}

/*
 * checks if login sequence can start, creates new context, etc
 */
static void server_login_accept(wzd_context_t * context)
{
  wzd_thread_t thread;
  wzd_thread_attr_t thread_attr;
  char inet_buf[INET6_ADDRSTRLEN]; /* usually 46 */
  unsigned char * userip;
  int ret;

  userip = context->hostip;
#if defined(IPV6_SUPPORT)
  if (context->family == WZD_INET6) {
    inet_ntop(AF_INET6,userip,inet_buf,INET6_ADDRSTRLEN);
    if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(userip)))
      out_log(LEVEL_INFO,"IP is IPv4 compatible\n");
  } else
#endif
  {
    inet_ntop(AF_INET,userip,inet_buf,INET_ADDRSTRLEN);
  }

  /* switch to tls mode ? */
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (mainConfig->tls_type == TLS_IMPLICIT) {
    if (tls_auth("SSL",context)) {
      close(context->controlfd);
      FD_UNREGISTER(context->controlfd,"Client socket");
      out_log(LEVEL_HIGH,"TLS switch failed (implicit) from client %s\n", inet_buf);
      /* mark context as free */
      context->magic = 0;
      /** \todo FIXME context is NOT freed */
      return;
    }
    context->connection_flags |= CONNECTION_TLS;
  }
  context->ssl.data_mode = TLS_CLEAR;
#endif

  if (CFG_GET_OPTION(mainConfig,CFG_OPT_CHECKIP_LOGIN)) {
    ret = check_ip_before_login(context);
    if (ret) {
      close(context->controlfd);
      FD_UNREGISTER(context->controlfd,"Client socket");
      out_log(LEVEL_NORMAL,"INFO rejected connection from %s\n",inet_buf);
      /* mark context as free */
      context->magic = 0;
      /** \todo FIXME context is NOT freed */
      return;
    }
  }

  /* start new thread */

  ret = wzd_thread_attr_init( & thread_attr );
  if (ret) {
    out_err(LEVEL_CRITICAL,"Unable to initialize thread attributes !\n");
    return;
  }
  if (wzd_thread_attr_set_detached( & thread_attr )) {
    out_err(LEVEL_CRITICAL,"Unable to set thread attributes !\n");
    return;
  }
  ret = wzd_thread_create(&thread,&thread_attr,clientThreadProc,context);
  if (ret) {
    out_err(LEVEL_CRITICAL,"Unable to create thread\n");
    return;
  }
  context->pid_child = (unsigned long)WZD_THREAD_VOID(&thread);
  wzd_thread_attr_destroy(&thread_attr); /* not needed anymore */
}

/*
 * removes timed out ident connections
 */
static void server_ident_timeout_check(void)
{
  ListElmt * elmnt;
  wzd_ident_context_t * ident_context;
  wzd_context_t * context;

  for (elmnt=server_ident_list.head; elmnt; elmnt=list_next(elmnt))
  {
lbl_ident_timeout_check_loop:
    if (!elmnt) break;
    ident_context = list_data(elmnt);
    if (!ident_context) continue;
    context = ident_context->context;

    if ( (server_time - context->login_time) > HARD_IDENT_TIMEOUT )
    {
      if (ident_context->read_fd > 0) socket_close(ident_context->read_fd);
      if (ident_context->write_fd > 0) socket_close(ident_context->write_fd);

      /* save value before freeing data */
      elmnt = list_next(elmnt);

      /* remove ident from list and accept login */
      server_ident_remove(ident_context);

      server_login_accept(context);

      /* restart checks at correct index */
      goto lbl_ident_timeout_check_loop;
    }
  }
}

/** \brief Server interruption handler
 *
 * Called when receiving SIGINT. Commit backend and exit immediatly.
 */
void interrupt(int signum)
{
  int ret;
  /* closing properly ?! */
#ifdef DEBUG
#if !defined(WIN32) && !defined(__sun__)
fprintf(stderr,"Received signal %s\n",sys_siglist[signum]);
#else
fprintf(stderr,"Received signal %d\n",signum);
#endif
#endif
  /* commit backend changes */
  ret = backend_commit_changes(mainConfig->backends->filename);
  if (ret) {
    out_log(LEVEL_CRITICAL,"Could not commit changes to backend !\n");
  }
  serverMainThreadExit(0);
}


uid_t get_server_uid(void)
{
#ifndef WIN32
  return getuid();
#else
  return GetCurrentProcessId();
#endif
}

void server_crashed(int signum)
{
  printf("Server has crashed of signal %d\n",signum);
#ifdef DEBUG
#ifndef WZD_DBG_NOABORT
  printf("I'll try to dump current memory to a core file (in the current dir)\n");
  printf("To use this core file you need to run:\n");
  printf("  gdb wzdftpd -core=core_file\n");
  printf("When prompted type be following command:\n");
  printf("  bt\n");
  abort();
#endif
#endif
}

/** \brief load config from structure to effective running config
 */
int server_switch_to_config(wzd_config_t *config)
{
  int fd;
  int ret;
  int err;
  wzd_string_t ** str_list;
  const char * ptr_to_data;
  char * ptr;
  int i;
  unsigned long ul;
  fd_t sock4, sock6;
  unsigned int port;
  server_ip_t * server_ip;
  char * ipaddress;
  char * port_ptr;

  WZD_ASSERT(config != NULL);

  str_list = config_get_string_list(config->cfg_file, "GLOBAL", "port", &err);
  if (str_list) {
    for (i=0; str_list[i]; i++) {
      sock4 = sock6 = -1;
      ptr_to_data = str_tochar(str_list[i]);
      out_log(LEVEL_FLOOD, "DEBUG: binding to ip %s\n", ptr_to_data);

      ipaddress = NULL;
      port = 0;

      /** \todo find a solution for dynamic ip
       *  \todo if we have a host name, it will unlikely contains ':'
       */
      if (strchr(ptr_to_data,':') != NULL) {
        /* specific bind */
        ipaddress = strdup(ptr_to_data);
        port_ptr = strrchr(ipaddress,':');
        *port_ptr++ = '\0';

        ul = strtoul(port_ptr, &ptr, 0);
        if (ptr && *ptr == '\0' && ul < 65536) {
          port = (unsigned int)ul;
        }
      } else {
        /* port number: assume we want to bind to all addresses */
        ul = strtoul(ptr_to_data, &ptr, 0);
        if (ptr && *ptr == '\0' && ul < 65536) {
          port = (unsigned int)ul;
        } else {
          out_log(LEVEL_HIGH, "ERROR: ip %s is invalid\n", ptr_to_data);
        }
      }

      /* try IPv6 first:
       * 1. set IPV6_V6ONLY for ipv6 socket before bind(2) if it is defined.
       * if IPV6_V6ONLY is defined and setsockopt() failed, warn it.
       * if IPV6_V6ONLY is defined and setsockopt() succeeded, let
       * v4inv6 1.
       *
       * 2. if bind(2) for an socket (either for ipv4 or ipv6) failed
       * when you already have socket (it is either ipv6 or ipv4,
       * respectively because the loop trys only for ipv4 and/or ipv6) and the reason is
       * EADDRINUSE and v4inv6 is 0, it is ok to ignore this "error."
       */
      if (ipaddress == NULL || strchr(ipaddress,':') != NULL)
        sock6 = socket_make(ipaddress,&port,config->max_threads,WZD_INET6);
      if (ipaddress == NULL || strchr(ipaddress,':') == NULL)
        sock4 = socket_make(ipaddress,&port,config->max_threads,WZD_INET4);

      if (sock4 == (fd_t)-1 && sock6 == (fd_t)-1) {
        out_log(LEVEL_CRITICAL,"FATAL Could not bind to ip %s\n",str_tochar(str_list[i]));
        str_deallocate_array(str_list);
        return -1;
      }

      if (sock6 != (fd_t)-1) {
        server_ip = wzd_malloc(sizeof(*server_ip));
        server_ip->dynamic = 0;
        server_ip->ip = wzd_strdup(ptr_to_data);
        server_ip->sock = sock6;
        FD_REGISTER(sock6,"Server listening socket");
        if (list_ins_next(&server_ip_list, NULL, server_ip)) {
          out_log(LEVEL_CRITICAL,"FATAL Could not register server ip %s\n",ptr_to_data);
          server_ip_free(server_ip);
          str_deallocate_array(str_list);
          return -1;
        }
        {
          int one=1;

          if (setsockopt(sock6, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
            out_log(LEVEL_CRITICAL,"setsockopt(SO_KEEPALIVE");
            str_deallocate_array(str_list);
            return -1;
          }
        }
      }
      if (sock4 != (fd_t)-1) {
        server_ip = wzd_malloc(sizeof(*server_ip));
        server_ip->dynamic = 0;
        server_ip->ip = wzd_strdup(ptr_to_data);
        server_ip->sock = sock4;
        FD_REGISTER(sock4,"Server listening socket");
        if (list_ins_next(&server_ip_list, NULL, server_ip)) {
          out_log(LEVEL_CRITICAL,"FATAL Could not register server ip %s\n",ptr_to_data);
          server_ip_free(server_ip);
          str_deallocate_array(str_list);
          return -1;
        }
        {
          int one=1;

          if (setsockopt(sock4, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
            out_log(LEVEL_CRITICAL,"setsockopt(SO_KEEPALIVE");
            str_deallocate_array(str_list);
            return -1;
          }
        }
      }

    }
    str_deallocate_array(str_list);
  }

/** \bug XXX FIXME polling with select on named pipe seems to fail ... */
#if 0
  /* set up control named pipe */
  out_log(LEVEL_INFO, "Creating named pipe\n");
#ifndef _MSC_VER
#else /* _MSC_VER */

#define PIPE_BUFSIZE 4096
  {
    HANDLE hpipe;
    LPTSTR pipeName = "\\\\.\\pipe\\wzdftpd";
    int fdp;

    hpipe = CreateNamedPipe(
      pipeName,
      PIPE_ACCESS_DUPLEX, /* read/write access */
      PIPE_TYPE_MESSAGE |
      PIPE_READMODE_MESSAGE |
      PIPE_NOWAIT,
      PIPE_UNLIMITED_INSTANCES,
      PIPE_BUFSIZE,     /* output buffer size */
      PIPE_BUFSIZE,     /* input buffer size */
      NMPWAIT_USE_DEFAULT_WAIT,
      NULL);

    if (hpipe == INVALID_HANDLE_VALUE) {
      out_log(LEVEL_HIGH,"Could not create pipe");
    }

    fdp = _open_osfhandle((long)hpipe,0);
    out_log(LEVEL_FLOOD,"Named pipe created, fd: %d\n",fdp);

    config->controlfd = fdp;
    FD_REGISTER(mainConfig->controlfd,"Server control fd");
  }
#endif /* _MSC_VER */
#endif /* 0 */

#ifndef WIN32
  /* if running as root, we must give up root rigths for security */
  {
    /* effective uid if 0 if run as root or setuid */
    if (geteuid() == 0) {
      /* do we change gid ? */
      if (getlib_server_gid() != getegid())
      {
        out_log(LEVEL_INFO,"Giving up root rights for group %ld (current gid %ld)\n",getlib_server_gid(),getgid());
        setgid(getlib_server_gid());
      }

      out_log(LEVEL_INFO,"Giving up root rights for user %ld (current uid %ld)\n",getlib_server_uid(),getuid());
      setuid(getlib_server_uid());
    }
  }
#endif /* WIN32 */


  context_list = wzd_malloc(sizeof(List));

  list_init(context_list, (void (*)(void*))context_free);

#ifdef WIN32
  /* cygwin sux ... shared library variables are NOT set correctly
   * on dlopenin'
   * remember me to slap the one who told me to make this prog portable ... oops
   * it's me °_°
   */
  setlib_mainConfig(config);
  setlib_contextList(context_list);
#endif /* WIN32 */


  /* create server mutex */
  WZD_ASSERT( server_mutex == NULL );
  server_mutex = wzd_mutex_create((unsigned long)config); /* use the pointer as key .. */

  /* create limiter mutex */
  limiter_mutex = wzd_mutex_create((unsigned long)config+1);


  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (mainConfig->backends == NULL) {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    return -1;
  }
  ret = backend_init(config->backends);
  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (ret) {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    return -1;
  }

  /** \todo XXX FIXME open log dir */
  if (config->logdir) {
    fs_filestat_t s;
    if (fs_file_stat(config->logdir,&s)) {
      out_log(LEVEL_HIGH,"Could not open log dir (%s)\n", config->logdir);
      return 1;
    }
    if (!S_ISDIR(s.mode)) {
      out_log(LEVEL_HIGH,"Log dir (%s) is NOT a directory, I'm confused!\n", config->logdir);
      return 1;
    }
  }

  if (config->xferlog_name) {
    fd = xferlog_open(config->xferlog_name, 0600);
    if (fd == -1)
    {
      out_log(LEVEL_HIGH,"Could not open xferlog (%s)\n", config->xferlog_name);
      return 1;
    }
    config->xferlog_fd = fd;
  }


  if (config->pid_file) {
    fd = open(config->pid_file, O_RDONLY, 0644);
    if (fd != -1)
    {
      unsigned long l,size;
      char buf[64];
      char *ptr;
      int ret;

      size = read(fd,buf,64);
      if (size <= 0) {
        out_log(LEVEL_HIGH,"pid_file already exist and is invalid ! (%s)\nRemove it if you are sure",config->pid_file);
        close(fd);
        return 1;
      }
      l = strtoul(buf,&ptr,10);
      if (*ptr != '\n' && *ptr != '\r' && *ptr != '\0')
      {
        out_log(LEVEL_HIGH,"pid_file already exist and is invalid ! (%s)\nRemove it if you are sure",config->pid_file);
        close(fd);
        return 1;
      }
      close(fd);
      /* check no process is running with this pid */
#ifndef WIN32
      ret = kill(l,0);
#else
      /*    ret = raise(l);*/ /* TODO XXX FIXME raise send signal to EXECUTING process ... */
      ret = -1;
      errno = ESRCH;
#endif
      if (!ret || (ret==-1 && errno==EPERM)) {
        out_log(LEVEL_CRITICAL,"Error: pid file (%s) contains the pid of a running process\n",config->pid_file);
        return 1;
      }
      if ( !(ret==-1 && errno==ESRCH) ) {
        out_log(LEVEL_CRITICAL,"Error: pid file: %s\n",config->pid_file);
        out_log(LEVEL_CRITICAL,"kill(%ld,0) returned %d, errno=%d (%s)\n",
            l, ret, errno, strerror(errno));
        out_log(LEVEL_CRITICAL,"file: %s:%d\n",__FILE__,__LINE__);
        return 1;
      }
      out_log(LEVEL_HIGH,"Warning: removing old pid file (%s)\n",config->pid_file);
      if (unlink(config->pid_file)) {
        out_log(LEVEL_HIGH,"Could not remove pid_file (%s)\n",config->pid_file);
        return 1;
      }
    }

    /* creates pid file */
    {
      char buf[64];
#ifndef WIN32
      fd = open(config->pid_file,O_WRONLY | O_CREAT | O_EXCL,0644);
#else
      /* ignore if file exists for visual version ... */
      fd = open(config->pid_file,O_WRONLY | O_CREAT,0644);
#endif
      snprintf(buf,64,"%ld\n",(unsigned long)getpid());
      if (fd==-1) {
        out_log(LEVEL_CRITICAL,"Unable to open pid file %s: %s\n",config->pid_file,strerror(errno));
        free_config(config);
        exit(1);
      }
      ret = write(fd,buf,strlen(buf));
      close(fd);
    }
  } else {
    out_log(LEVEL_NORMAL,"INFO: not using pid_file\n");
  }






  return 0;
}


/************************************************************************/
/*********************** SERVER MAIN THREAD *****************************/
/************************************************************************/

/** \brief Server side main loop
 *
 * Initialize config and modules, and run the main loop: check for incoming
 * connections / ident connections, run cron jobs
 */
void serverMainThreadProc(void *arg)
{
  int ret;
  unsigned long max_wait_time;
  fd_set r_fds, w_fds, e_fds;
  fd_t maxfd;
  struct timeval tv;

#ifndef WIN32
  /* catch broken pipe ! */
#ifdef __SVR4
  sigignore(SIGPIPE);
#else
  signal(SIGPIPE,SIG_IGN);
#endif
#endif /* _MSC_VER */

  signal(SIGINT,interrupt);
  signal(SIGTERM,interrupt);
#ifndef WIN32
/*  signal(SIGKILL,interrupt);*/ /* SIGKILL signal is uncatchable */

  signal(SIGHUP,server_restart);
#endif

#ifdef SIGSYS
  signal(SIGSYS,interrupt);
#endif /* SIGSYS */

#ifndef WIN32
  {
    /* block signals so that other threads possibly created later (for ex.
     * in modules) do not receive signals like SIGINT
     */
    sigset_t oldmask, newmask;
    sigfillset(&newmask);
    ret = pthread_sigmask(SIG_BLOCK,&newmask,&oldmask);
    WZD_ASSERT_VOID( ret == 0 );
  }
#endif

#if defined(POSIX) && ! defined(BSD) /* NO, windows is NOT posix ! */
  /* set fork() limit */
  {
    struct rlimit rlim;

    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rlim);
  }
#endif /* POSIX */

#ifndef _WIN32
#if defined(DEBUG) && !defined(__CYGWIN__)
  signal(SIGSEGV,server_crashed);
#else
  {
    struct rlimit rlim;

    /* no core file ! */
    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rlim);
  }
#endif
#endif /* _WIN32 */

  /******** init shm *******/
  /* do this _before_ loading config, config can use it ! */
  vars_shm_init();
  server_mutex_set_init();

  end_mutex = wzd_mutex_create(0x4321);

  /********* set up functions *******/
#if 0
  if (commands_init()) {
    out_log(LEVEL_HIGH,"Could not set up functions\n");
  }

  if (commands_add_defaults()) {
    out_log(LEVEL_HIGH,"Could not set up default functions\n");
  }
#endif

  /* clear ip list */
  list_init(&server_ip_list, server_ip_free);


  if (server_switch_to_config(mainConfig))
  {
    out_log(LEVEL_CRITICAL,"ERROR: couldn't switch to config, aborting !\n");
    serverMainThreadExit(-1);
  }



  /* clear ident list */
  list_init(&server_ident_list, free);


  /********** set up crontab ********/
  cronjob_add(&mainConfig->crontab,check_server_dynamic_ip,"fn:check_server_dynamic_ip",HARD_DYNAMIC_IP_INTVL,
      "*","*","*","*");
  cronjob_add(&mainConfig->crontab,commit_backend,"fn:commit_backend",HARD_COMMIT_BACKEND_INTVL,
      "*","*","*","*");
#ifdef HAVE_GNUTLS
  /* we will regenerate DH parameters each day at 2h35 am */
  if (cronjob_add(&mainConfig->crontab, tls_dh_params_regenerate, "fn:tls_dh_params_regenerate",
        "35","2","*","*","*"))
    out_log(LEVEL_HIGH,"TLS: error adding cron job _dh_params_regenerate\n");
#endif

  crontab_start(&mainConfig->crontab);


  /********** init modules **********/
  {
    wzd_module_t *module;
    module = mainConfig->module;
    while (module) {
      ret = module_load(module);
      module = module->next_module;
    }
  }

  /********** daemon mode ***********/
#ifndef DEBUG
  close(0);
  close(1);
  close(2);
#endif

#ifndef WIN32
  {
    /* restore signals so we can be stopped with SIGINT or restarted with SIGHUP */
    sigset_t oldmask, newmask;
    sigfillset(&newmask);
    ret = pthread_sigmask(SIG_UNBLOCK,&newmask,&oldmask);
    WZD_ASSERT_VOID( ret == 0 );
  }
#endif

  out_log(LEVEL_INFO,"Process %d ok\n",getpid());

  /* get value for server tick */
  max_wait_time = config_get_integer(mainConfig->cfg_file, "GLOBAL", "server tick", &ret);
  if (ret != CF_OK) {
    max_wait_time = DEFAULT_SERVER_TICK;
  }

  /* sets start time, for uptime */
  time(&mainConfig->server_start);

  /* reset stats */
  /** \todo load stats ! */
  reset_stats(&mainConfig->stats);

  out_log(LEVEL_HIGH,"%s started (build %s)\n",WZD_VERSION_STR,WZD_BUILD_NUM);

  /* now waiting for a connection */
  out_log(LEVEL_FLOOD,"Waiting for connections (main)\n");

  mainConfig->serverstop=0;
  while (!mainConfig->serverstop) {
    FD_ZERO(&r_fds);
    FD_ZERO(&w_fds);
    FD_ZERO(&e_fds);

    tv.tv_sec = max_wait_time; tv.tv_usec = 0;
    maxfd = 0;
    server_ip_select(&r_fds, &w_fds, &e_fds, &maxfd);
    server_ident_select(&r_fds, &w_fds, &e_fds, &maxfd);
    server_control_select(&r_fds, &w_fds, &e_fds, &maxfd);
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    ret = select(0, &r_fds, &w_fds, &e_fds, &tv);
#else
    ret = select(maxfd+1, &r_fds, &w_fds, &e_fds, &tv);
#endif

/*    out_err(LEVEL_FLOOD,".");*/
/*    fflush(stderr);*/

    switch (ret) {
    case -1: /* error */
      if (errno == EINTR) continue; /* retry */
      if (errno == EBADF) {
        out_log(LEVEL_CRITICAL,"FATAL Bad file descriptor\n");
        serverMainThreadExit(-1);
      }
      out_log(LEVEL_CRITICAL,"select failed (%s) :%s:%d\n",
        strerror(errno), __FILE__, __LINE__);
      serverMainThreadExit(-1);
      /* we abort, so we never returns */
#if 0
    case 0: /* timeout */
      /* check for timeout logins */
      break;
#endif
    default: /* input */
      time (&server_time);

      server_control_check(&r_fds,&w_fds,&e_fds);
      server_ident_check(&r_fds,&w_fds,&e_fds);
      /* check ident timeout */
      server_ident_timeout_check();
      server_ip_check(&r_fds,&w_fds,&e_fds);
    }

  } /* while (!serverstop) */


  /* commit backend changes */
  ret = backend_commit_changes(mainConfig->backends->filename);
  if (ret) {
    out_log(LEVEL_CRITICAL,"Could not commit changes to backend !\n");
  } else
    out_log(LEVEL_INFO,"Backend commited\n");
  serverMainThreadExit(0);
}

/** \deprecated ! use \ref cfg_free */
static void free_config(wzd_config_t * config)
{
/*  limiter_free(mainConfig->limiter_ul);
  limiter_free(mainConfig->limiter_dl);*/

  if (mainConfig->xferlog_fd >= 0)
    xferlog_close(mainConfig->xferlog_fd);

  if (CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG)) {
#ifndef WIN32
    closelog();
#endif
  }
  wzd_free(mainConfig->logfilename);
  wzd_free(mainConfig->config_filename);
  wzd_free(mainConfig->pid_file);
  wzd_free(mainConfig->dir_message);

  wzd_free(mainConfig);
}

void serverMainThreadExit(int retcode)
{
  static int finished = 0;

  wzd_mutex_lock(end_mutex);

  if (++finished > 1) exit(0); /* already finished ? */

  out_log(LEVEL_HIGH,"Server exiting, retcode %d\n",retcode);

  /* ignore standard signals from now, we are exiting */
#ifndef _MSC_VER
  signal(SIGINT,SIG_IGN);
#endif

  crontab_stop();

  list_destroy(&server_ip_list);

  if (mainConfig->controlfd != (fd_t)-1) {
    close(mainConfig->controlfd);
    FD_UNREGISTER(mainConfig->controlfd,"Server control fd");
  }
#ifdef WZD_MULTITHREAD
  /* kill all childs threads */
  out_log(LEVEL_INFO,"Sending EXIT signal to child threads\n");
  if (context_list)
  {
    ListElmt * elmnt;
    wzd_context_t * loop_context;
    for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
    {
      if ((loop_context = list_data(elmnt)))
        loop_context->exitclient = 1;
    }
  }
#endif
  out_log(LEVEL_INFO,"Waiting for the last child to exit\n");
  {
    unsigned int child_count;
    int ok = 0;
    int loop_count=0;

    if (context_list) {
      while (!ok) {
        ListElmt * elmnt;
        wzd_context_t * loop_context;
        child_count = 0;
        for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
        {
          loop_context = list_data(elmnt);
          if (loop_context->magic == CONTEXT_MAGIC) child_count++;
        }
        if (child_count == 0) { ok=1; break; }
        out_log(LEVEL_FLOOD,"Found %d child threads, waiting ..\n",child_count);
#ifndef WIN32
        usleep(300000);
#else
        Sleep(300);
#endif
        if (++loop_count > 10) { /* maximum wait time: ~ 3s */
          out_log(LEVEL_INFO,"Still %d childs .. exiting anyway\n",child_count);
          break;
        }
      }
    }
  }
  /* we need to wait for child threads to be effectively dead */
#ifndef WIN32
  usleep(300000);
#else
  Sleep(300);
#endif
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  tls_exit();
#endif
  wzd_cache_purge();
  vars_shm_free();
  utf8_end(mainConfig);
  server_clear_param(&mainConfig->param_list);
  hook_free(&mainConfig->hook);
  hook_free_protocols();
  module_free(&mainConfig->module);
  /** \todo XXX close ALL backends */
  backend_close(mainConfig->backends->filename);
  cronjob_free(&mainConfig->crontab);
  section_free(&mainConfig->section_list);
  vfs_free(&mainConfig->vfs);
  free_messages();

  user_free_registry();
  group_free_registry();

  if (limiter_mutex) wzd_mutex_destroy(limiter_mutex);
  if (server_mutex) wzd_mutex_destroy(server_mutex);

  list_destroy(&server_ident_list);
  list_destroy(context_list);
  wzd_free(context_list);

  context_list = NULL;

  log_fini();

  /* free(mainConfig); */
  unlink(mainConfig->pid_file);
  cfg_free(mainConfig);
  mainConfig = NULL;
  server_mutex_set_fini();

  wzd_debug_fini();

#if defined(_MSC_VER)
  WSACleanup();
#endif

#ifdef DEBUG
  /* reset color, there can be some bad control codes ... */
  fprintf(stdout,"%s",CLR_NOCOLOR);
  fprintf(stderr,"%s",CLR_NOCOLOR);
#endif

#ifndef WIN32
  /* restore default handler for SIGSEGV before exiting
   */
  signal(SIGSEGV,SIG_DFL);
#endif

  wzd_mutex_unlock(end_mutex);
  wzd_mutex_destroy(end_mutex);

  exit (retcode);
}

/*! @} */

