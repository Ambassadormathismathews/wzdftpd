/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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

#if defined(_MSC_VER)
#include <winsock2.h>
#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#endif /* _MSC_VER */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#ifndef _MSC_VER
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

#ifdef WIN32
/* cygwin does not support ipv6 */
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#endif

#include "wzd_structs.h"

#include "wzd_misc.h"
#include "wzd_log.h"
#include "wzd_tls.h"
#include "wzd_init.h"
#include "wzd_libmain.h"
#include "wzd_ServerThread.h"
#include "wzd_ClientThread.h"
#include "wzd_vfs.h"
#include "wzd_perm.h"
#include "wzd_socket.h"
#include "wzd_mod.h"
#include "wzd_cache.h"
#include "wzd_crontab.h"
#include "wzd_messages.h"
#include "wzd_section.h"
#include "wzd_site.h"

#include "wzd_debug.h"

#define BUFFER_LEN	4096

/************ PROTOTYPES ***********/
void serverMainThreadProc(void *arg);
void serverMainThreadExit(int);
void server_crashed(int signum);

void child_interrupt(int signum);
void reset_stats(wzd_server_stat_t * stats);

int check_server_dynamic_ip(void);
int commit_backend(void);
void server_rebind(const unsigned char *new_ip, unsigned int new_port);

/************ VARS *****************/
wzd_config_t *	mainConfig;
wzd_shm_t *	mainConfig_shm;

wzd_context_t *	context_list;
wzd_shm_t *	context_shm;

wzd_sem_t	limiter_sem;

wzd_cronjob_t	* crontab;

/*time_t server_start;*/

short created_shm=0;


/************ PUBLIC **************/
int runMainThread(int argc, char **argv)
{
  serverMainThreadProc(0);

  return 0;
}

/************ PRIVATE *************/

static void free_config(wzd_config_t * config);

static unsigned int server_ident_list[3*HARD_USERLIMIT];
static int server_add_ident_candidate(unsigned int socket_accept_fd);
static void server_ident_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, unsigned int * maxfd);
static void server_ident_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds);
static void server_ident_remove(int index);
static void server_ident_timeout_check(void);

static void server_login_accept(wzd_context_t * context);

time_t server_time;



static void cleanchild(int nr) {
#ifndef _MSC_VER
  wzd_context_t * context;
  int i;
  pid_t pid;

  if (!context_list) return;
  out_log(LEVEL_FLOOD,"cleanchild nr:%d\n",nr);
  while (1) {
    
    if ( (pid = wait3(NULL, WNOHANG, NULL)) > 0)
    {
      context = &context_list[0];
      out_log(LEVEL_FLOOD,"Child %u exiting\n",pid);
      /* TODO search context list and cleanup context */
      for (i=0; i<HARD_USERLIMIT; i++)
      {
        if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) {
#ifdef DEBUG
          fprintf(stderr,"Context found for pid %u - cleaning up\n",pid);
#endif
          client_die(&context_list[i]);
          break;
        }
      }
      if (i == HARD_USERLIMIT) break; /* context not found ?! */
    } else { /* no more childs */
      break;
    } /* if */
  } /* while */

/*  if (nr == context->pid_child) {
    context->pid_child = 0;
  }*/
#endif /* _MSC_VER */
}

static void context_init(wzd_context_t * context)
{
  context->magic = 0;
  memset(context->hostip,0,4);
  context->controlfd = -1;
  context->datafd = -1;
  context->portsock = 0;
  context->pasvsock = -1;
  context->dataport=0;
  context->resume = 0;
  context->thread_id = (unsigned long)-1;
  context->pid_child = 0;
  context->state = STATE_UNKNOWN;
  context->datamode = DATA_PORT;
  context->current_action.token = TOK_UNKNOWN;
  context->connection_flags = 0;
/*  context->current_limiter = NULL;*/
  context->current_ul_limiter.maxspeed = 0;
  context->current_ul_limiter.bytes_transfered = 0;
  context->current_dl_limiter.maxspeed = 0;
  context->current_dl_limiter.bytes_transfered = 0;
#ifdef HAVE_OPENSSL
  context->ssl.obj = NULL;
  context->ssl.data_ssl = NULL;
#endif
  context->read_fct = (read_fct_t)clear_read;
  context->write_fct = (write_fct_t)clear_write;
}

static wzd_context_t * context_find_free(wzd_context_t * context_list)
{
  wzd_context_t * context=NULL;
  int i=0;

  while (i<HARD_USERLIMIT) {
    if (context_list[i].magic == 0) {
      /* cleanup context */
      context_init(context_list+i);
      return (context_list+i);
    }
#ifdef DEBUG
    if (context_list[i].magic != CONTEXT_MAGIC) {
fprintf(stderr,"*** CRITICAL *** context list could be corrupted at index %d\n",i);
    }
#endif /* DEBUG */
    i++;
  }

  return context;
}

void reset_stats(wzd_server_stat_t * stats)
{
  stats->num_connections = 0;
  stats->num_childs = 0;
}

/** \return 1 if ip is ok, 0 if ip is denied, -1 if ip is not in list */
int global_check_ip_allowed(unsigned char userip[4])
{
  char ip[30];

  snprintf(ip,30,"%hhu.%hhu.%hhu.%hhu",userip[0],userip[1],userip[2],userip[3]);
  switch (mainConfig->login_pre_ip_check) {
  case 1: /* order allow, deny */
    if (ip_inlist(mainConfig->login_pre_ip_allowed,ip)==1) return 1;
    if (ip_inlist(mainConfig->login_pre_ip_denied,ip)==1) return 0;
    break;
  case 2: /* order deny, allow */
    if (ip_inlist(mainConfig->login_pre_ip_denied,ip)==1) return 0;
    if (ip_inlist(mainConfig->login_pre_ip_allowed,ip)==1) return 1;
    break;
  }
  return -1;
}

/** called when SIGHUP received, need to restart the main server
 * (and re-read config file)
 * Currently loggued users are NOT kicked
 */
void server_restart(int signum)
{
  wzd_config_t * config;
  int sock;
  int rebind=0;

  fprintf(stderr,"Sighup received\n");

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
    memcpy(mainConfig->pasv_ip,config->pasv_ip,4);
    mainConfig->login_pre_ip_check = config->login_pre_ip_check;
    /* reload pre-ip lists */
    /* reload vfs lists */
    vfs_free(&mainConfig->vfs);
    mainConfig->vfs = config->vfs;
    /* do not touch hooks */
    /* do not touch modules */
#ifdef HAVE_OPENSSL
    /* what can we do with ssl ? */
    /* reload certificate ? */
#endif
    /* we currently do NOT support shm_key dynamic change */
    /* reload permission list ?? */
    /* reload global_ul_limiter ?? */
    /* reload global_dl_limiter ?? */
    mainConfig->site_config = config->site_config;
    /* do not touch user_list */
    /* do not touch group list */
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
    struct stat s;
    fclose(mainConfig->logfile);
    fd = open(mainConfig->logfilename,mainConfig->logfilemode,0640);
    mainConfig->logfile = fdopen(fd,"a");
    if (mainConfig->logfile==NULL) {
      out_err(LEVEL_CRITICAL,"Could not reopen log file !!!\n");
    }
    if (mainConfig->xferlog_name && !fstat(fd,&s)) {
      close(mainConfig->xferlog_fd);
#if (defined (__FreeBSD__) && (__FreeBSD__ < 5)) || defined(_MSC_VER)
      fd = open(mainConfig->xferlog_name,O_WRONLY | O_CREAT | O_APPEND ,0600);
#else /* ! BSD */
      fd = open(mainConfig->xferlog_name,O_WRONLY | O_CREAT | O_APPEND | O_SYNC,0600);
#endif /* BSD */
      if (fd==-1)
        out_log(LEVEL_HIGH,"Could not open xferlog file: %s\n",
            mainConfig->xferlog_name);
      mainConfig->xferlog_fd = fd;
    }
  }
}

void server_rebind(const unsigned char *new_ip, unsigned int new_port)
{
  int sock;
  const unsigned char *ip = (new_ip) ? new_ip : mainConfig->ip;

  /* create socket iff different ports ?! */
  sock = mainConfig->mainSocket;
  close(sock);

  sock = mainConfig->mainSocket = socket_make((const char *)ip,&new_port,mainConfig->max_threads);
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

/* checks if dynamic ip has changed, and rebind main socket if true
 */
int check_server_dynamic_ip(void)
{
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

  if (mainConfig->dynamic_ip[0]=='+')
  {
    const char *ip = (const char *)mainConfig->dynamic_ip;
    ip++;

   /* 2- resolve config ip */
    if (strcmp(ip,"*")==0)
      sa_config.sin_addr.s_addr = htonl(INADDR_ANY);
    else
    {
      struct hostent* host_info;
      // try to decode dotted quad notation
#ifdef WIN32
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
      out_log(LEVEL_HIGH,"Rebinding main server ! (from %d.%d.%d.%d to %d.%d.%d.%d)\n",
          str_ip_current[0],str_ip_current[1],str_ip_current[2],str_ip_current[3],
          str_ip_config[0],str_ip_config[1],str_ip_config[2],str_ip_config[3]);
      server_rebind((const unsigned char *)inet_ntoa(sa_config.sin_addr),mainConfig->port);
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
}


int commit_backend(void)
{
  /* TODO XXX FIXME flush backend IFF modified ! */
  if (!mainConfig) return 1;
  backend_commit_changes(mainConfig->backend.name);
  return 0;
}


/*
 * add a connection to the list of idents to be checked
 */
static int server_add_ident_candidate(unsigned int socket_accept_fd)
{
  unsigned char remote_host[16];
  unsigned int remote_port;
  char inet_buf[INET6_ADDRSTRLEN]; /* usually 46 */
  unsigned char userip[16];
  int newsock, fd_ident;
  unsigned short ident_port = 113;
  wzd_context_t	* context;
  int context_index;
  int i;

  newsock = socket_accept(mainConfig->mainSocket, remote_host, &remote_port);
  if (newsock <0)
  {
    out_log(LEVEL_HIGH,"Error while accepting\n");
    serverMainThreadExit(-1); /** \todo do not exit server, just client */
  }
  FD_REGISTER(newsock,"Client control socket");

  memcpy(userip,remote_host,16);

#if !defined(IPV6_SUPPORT)
  inet_ntop(AF_INET,userip,inet_buf,INET_ADDRSTRLEN);
#else
  inet_ntop(AF_INET6,userip,inet_buf,INET6_ADDRSTRLEN);
  if (IN6_IS_ADDR_V4MAPPED(userip))
    out_log(LEVEL_NORMAL,"IP is IPv4 compatible\n");
#endif

  /* Here we check IP BEFORE starting session */
  /* do this iff login_pre_ip_check is enabled */
  if (mainConfig->login_pre_ip_check &&
        global_check_ip_allowed(userip)<=0) { /* IP was rejected */
    /* close socket without warning ! */
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    out_log(LEVEL_HIGH,"Failed login from %s: global ip rejected\n",
      inet_buf);
    return 1;
  }

  out_log(LEVEL_NORMAL,"Connection opened from %s\n", inet_buf);
    
  /* 1. create new context */
  context = context_find_free(context_list);
  if (!context) {
    out_log(LEVEL_CRITICAL,"Could not get a free context - hard user limit reached ?\n");
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    return 1;
  }
  context_index = ( (unsigned long)context-(unsigned long)context_list ) / sizeof(wzd_context_t);

  /* don't forget init is done before */
  context->magic = CONTEXT_MAGIC;
  context->state = STATE_CONNECTING;
  context->controlfd = newsock;
  time (&context->login_time);

  memcpy(context->hostip,userip,16);

  /* try to open ident connection */
  /** \todo TODO XXX FIXME remove this hardcoded WZD_INET4 and use connection type */
#if defined(IPV6_SUPPORT)
  fd_ident = socket_connect(userip,WZD_INET6,ident_port,0,newsock,HARD_IDENT_TIMEOUT);
#else
  fd_ident = socket_connect(userip,WZD_INET4,ident_port,0,newsock,HARD_IDENT_TIMEOUT);
#endif

  if (fd_ident == -1) {
#ifdef _MSC_VER
    errno = h_errno;
#endif
    if (errno == ENOTCONN || errno == ECONNREFUSED || errno == ETIMEDOUT) {
      server_login_accept(context);
      return 0;
    }
    out_log(LEVEL_INFO,"Could not get ident (error: %s)\n",strerror(errno));
    socket_close(newsock);
    FD_UNREGISTER(newsock,"Client socket");
    return 1;
  }
  FD_REGISTER(fd_ident,"Ident socket"); /** \todo add more info to description: client number, etc */

  /* add connection to ident list */
  i=0;
  while (server_ident_list[i] != -1 || server_ident_list[i+1] != -1) i += 3;
  server_ident_list[i] = -1; /* read */
  server_ident_list[i+1] = fd_ident; /* write */
  server_ident_list[i+2] = context_index;
  server_ident_list[i+3] = -1;
  server_ident_list[i+4] = -1;
  server_ident_list[i+5] = -1;

  return 0;
}

/*
 * add idents to the correct fd_set
 */
static void server_ident_select(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds, unsigned int * maxfd)
{
  int i=0;

  while (server_ident_list[i] != -1 || server_ident_list[i+1] != -1) {
    if (server_ident_list[i] != -1)
    {
      FD_SET(server_ident_list[i],r_fds);
      FD_SET(server_ident_list[i],e_fds);
      *maxfd = MAX(*maxfd,server_ident_list[i]);
    }
    if (server_ident_list[i+1] != -1)
    {
      FD_SET(server_ident_list[i+1],w_fds);
      FD_SET(server_ident_list[i+1],e_fds);
      *maxfd = MAX(*maxfd,server_ident_list[i+1]);
    }
    i += 3;
  }
}

/*
 * add a connection to the list of idents to be checked
 */
static void server_ident_check(fd_set * r_fds, fd_set * w_fds, fd_set * e_fds)
{
  char buffer[BUFFER_LEN];
  const char * ptr;
  int i=0;
  wzd_context_t * context;
  unsigned short remote_port;
  unsigned short local_port;
  int fd_ident;
  int ret;

  while (server_ident_list[i] != -1 || server_ident_list[i+1] != -1) {
    if (server_ident_list[i] != -1)
    {
      if (FD_ISSET(server_ident_list[i],e_fds)) { /* error */
        /* remove ident connection from list and continues with no ident */
        goto continue_connection;
      }
      if (FD_ISSET(server_ident_list[i],r_fds)) { /* get ident */
        fd_ident = server_ident_list[i];
        context = &context_list[server_ident_list[i+2]];

        /* 4- try to read response */
        ret = recv(fd_ident,buffer,sizeof(buffer),0);
        if (ret < 0) {
#ifdef _MSC_VER
          errno = WSAGetLastError();
          socket_close(fd_ident);
          FD_UNREGISTER(fd_ident,"Ident socket");
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
#endif
          if (errno == EINPROGRESS) continue;
          out_log(LEVEL_NORMAL,"error reading ident request %s\n",strerror(errno));
          socket_close(fd_ident);
          FD_UNREGISTER(fd_ident,"Ident socket");
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
        strncpy(context->ident,ptr,MAX_IDENT_LENGTH);
        chop(context->ident);

#ifdef WZD_DBG_IDENT
        out_log(LEVEL_NORMAL,"received ident %s\n",context->ident);
#endif

continue_connection:
        /* remove ident from list and accept login */
        server_ident_remove(i/3);

        server_login_accept(context);
      }
    }
    else if (server_ident_list[i+1] != -1)
    {
      if (FD_ISSET(server_ident_list[i+1],e_fds)) { /* error */
        /* remove ident connection from list and continues with no ident */
        goto continue_connection;
        ret = 0;
      }
      if (FD_ISSET(server_ident_list[i+1],w_fds)) { /* write ident request */
        fd_ident = server_ident_list[i+1];
        context = &context_list[server_ident_list[i+2]];

        /* 2- get local and remote ports */

        /* get remote port number */
        local_port = socket_get_local_port(context->controlfd);
        remote_port = socket_get_remote_port(context->controlfd);

        snprintf(buffer,BUFFER_LEN,"%u, %u\r\n",remote_port,local_port);

        /* 3- try to write */
        ret = send(fd_ident,buffer,strlen(buffer),0);
        if (ret < 0) {
#ifdef _MSC_VER
          errno = WSAGetLastError();
          socket_close(fd_ident);
          FD_UNREGISTER(fd_ident,"Ident socket");
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
#endif
          if (errno == EINPROGRESS) continue;
          out_log(LEVEL_NORMAL,"error sending ident request %s\n",strerror(errno));
          socket_close(fd_ident);
          FD_UNREGISTER(fd_ident,"Ident socket");
          /* remove ident connection from list and continues with no ident */
          goto continue_connection;
        }
        /* now we wait ident answer */
        server_ident_list[i] = fd_ident;
        server_ident_list[i+1] = -1;
      }
    }
    i += 3;
  }
}

/*
 * removes ident from list by replacing this entry by the last
 */
static void server_ident_remove(int index)
{
  int i;

  index *= 3;
  i = index;
  while (server_ident_list[i] != -1 && server_ident_list[i+1] != -1)
    i += 3;
  if (i == 0) { /* only one entry */
    server_ident_list[0] = -1;
    server_ident_list[1] = -1;
    server_ident_list[2] = -1;
    return;
  }
  i -= 3;

#ifdef DEBUG
  if (i < 0 || i >= 3*HARD_USERLIMIT)
    server_crashed(-1);
#endif

  server_ident_list[index]   = server_ident_list[i];
  server_ident_list[index+1] = server_ident_list[i+1];
  server_ident_list[index+2] = server_ident_list[i+2];
  server_ident_list[i]   = -1;
  server_ident_list[i+1] = -1;
  server_ident_list[i+2] = -1;
}

/*
 * checks if login sequence can start, creates new context, etc
 */
static void server_login_accept(wzd_context_t * context)
{
  char inet_buf[INET6_ADDRSTRLEN]; /* usually 46 */
  unsigned char * userip;
#ifdef WZD_MULTIPROCESS
#ifdef __CYGWIN__
  unsigned long shm_key = mainConfig->shm_key;
#endif /* __CYGWIN__ */
#endif /* WZD_MULTIPROCESS */

  userip = context->hostip;
#if !defined(IPV6_SUPPORT)
  inet_ntop(AF_INET,userip,inet_buf,INET_ADDRSTRLEN);
#else
  inet_ntop(AF_INET6,userip,inet_buf,INET6_ADDRSTRLEN);
  if (IN6_IS_ADDR_V4MAPPED(userip))
    out_log(LEVEL_NORMAL,"IP is IPv4 compatible\n");
#endif

  /* start child process */
#ifdef WZD_MULTIPROCESS
  if (fork()==0) { /* child */
    /* 0. get shared memory zones */
#ifdef __CYGWIN__
/*    mainConfig_shm = wzd_shm_create(shm_key-1,sizeof(wzd_config_t),0);*/
    mainConfig_shm = wzd_shm_get(shm_key-1,0);
    if (mainConfig_shm == NULL) {
      /* NOTE we do not have any out_log here, since we have no config !*/
      out_err(LEVEL_CRITICAL,"I can't open main config shm ! (child)\n");
      exit(1);
    }
    mainConfig = mainConfig_shm->datazone;
    setlib_mainConfig(mainConfig);
/*    context_shm = wzd_shm_create(shm_key,HARD_USERLIMIT*sizeof(wzd_context_t),0);*/
    context_shm = wzd_shm_get(shm_key,0);
    if (context_shm == NULL) {
      out_err(LEVEL_CRITICAL,"I can't open context shm ! (child)\n");
      exit(1);
    }
    context_list = context_shm->datazone;
    setlib_contextList(context_list);
    mainConfig->user_list = ((void*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t));
    mainConfig->group_list = ((void*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t)) + (HARD_DEF_USER_MAX*sizeof(wzd_user_t));

    {
      /* XXX FIXME only available for plaintext backend ? */
      typedef int (*set_user_fct)(wzd_user_t *);
      typedef int (*set_group_fct)(wzd_group_t *);
      set_user_fct uf;
      set_group_fct gf;
      uf = (set_user_fct)dlsym(mainConfig->backend.handle,"wzd_set_user_pool");
      gf = (set_group_fct)dlsym(mainConfig->backend.handle,"wzd_set_group_pool");
      if (uf && gf) {
        (uf)(mainConfig->user_list);
        (gf)(mainConfig->group_list);
      } else {
        exit(1);
      }
    }
#endif /* __CYGWIN__ */

    /* close unused fd */
    close (mainConfig->mainSocket);
    out_log(LEVEL_FLOOD,"Child %d created\n",getpid());

    /* redefines SIGTERM handler */
    signal(SIGTERM,child_interrupt);
#endif /* WZD_MULTIPROCESS */
    

    /* switch to tls mode ? */
#ifdef HAVE_OPENSSL
    if (mainConfig->tls_type == TLS_IMPLICIT) {
      if (tls_auth("SSL",context)) {
        close(context->controlfd);
        out_log(LEVEL_HIGH,"TLS switch failed (implicit) from client %s\n", inet_buf);
        /* mark context as free */
        context->magic = 0;
        return;
      }
      context->connection_flags |= CONNECTION_TLS;
    }
    context->ssl.data_mode = TLS_CLEAR;
#endif

#ifdef WZD_MULTIPROCESS
    /* for stats */
    mainConfig->stats.num_childs++;

    context->pid_child = getpid();
#else /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
#ifdef _MSC_VER
    {
      HANDLE thread;
      unsigned long threadID;

      thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)clientThreadProc, context, 0, &threadID);

      context->pid_child = (unsigned long)thread;
    }
#else /* WIN32 */
    {
      int ret;
      pthread_t thread;
      pthread_attr_t thread_attr;

      ret = pthread_attr_init(&thread_attr);
      if (ret) {
        out_err(LEVEL_CRITICAL,"Unable to initialize thread attributes !\n");
        return;
      }
      if (pthread_attr_setdetachstate(&thread_attr,PTHREAD_CREATE_DETACHED)) {
        out_err(LEVEL_CRITICAL,"Unable to set thread attributes !\n");
        return;
      }
      ret = pthread_create(&thread,&thread_attr,clientThreadProc,context);
      context->pid_child = (unsigned long)thread;
      pthread_attr_destroy(&thread_attr); /* not needed anymore */
    }
#endif /* _MSC_VER */
#else /* WZD_MULTITHREAD */
    clientThreadProc(context);
#endif /* WZD_MULTITHREAD */
#endif /* WZD_MULTIPROCESS */
#ifdef WZD_MULTIPROCESS
    exit (0);
  } else { /* parent */
    close (newsock);
  }
#endif
}

/*
 * removes timed out ident connections
 */
static void server_ident_timeout_check(void)
{
  int i;
  wzd_context_t * context;

  for (i=0; server_ident_list[i] != -1 || server_ident_list[i+1] != -1; i += 3)
  {
    context = &context_list[server_ident_list[i+2]];

    if ( (server_time - context->login_time) > HARD_IDENT_TIMEOUT )
    {
      if (server_ident_list[i]) socket_close(server_ident_list[i]);
      if (server_ident_list[i+1]) socket_close(server_ident_list[i+1]);
      /* remove ident from list and accept login */
      server_ident_remove(i/3);

      server_login_accept(context);
    }
  }
}

/** IMPERATIVE STOP REQUEST - exit */
void interrupt(int signum)
{
  int ret;
  /* closing properly ?! */
#ifdef DEBUG
#ifndef WIN32
fprintf(stderr,"Received signal %s\n",sys_siglist[signum]);
#else
fprintf(stderr,"Received signal %d\n",signum);
#endif
#endif
  /* commit backend changes */
  ret = backend_commit_changes(mainConfig->backend.name);
  if (ret) {
    out_log(LEVEL_CRITICAL,"Could not commit changes to backend !\n");
  }
  serverMainThreadExit(0);
}

#ifdef WZD_MULTIPROCESS
/** STOP REQUEST - child part */
void child_interrupt(int signum)
{
  wzd_context_t * context;
  int i;
  pid_t pid;

  pid = getpid();
#ifndef __CYGWIN__
  out_err(LEVEL_HIGH,"Child %d received signal %s\n",pid,sys_siglist[signum]);
#else
  out_err(LEVEL_HIGH,"Child %d received signal %d\n",pid,signum);
#endif

  context = &context_list[0];
  out_log(LEVEL_FLOOD,"Child %u exiting\n",pid);
  /* TODO search context list and cleanup context */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) {
#ifdef DEBUG
      fprintf(stderr,"Context found for pid %u - cleaning up\n",pid);
#endif
      client_die(&context_list[i]);

#ifdef HAVE_OPENSSL
      tls_free(&context_list[i]);
#endif
      break;
    }
  }

  exit(0);
}
#endif /* WZD_MULTIPROCESS */

/* \return 0 if ok, -1 if error, 1 if trying to kill myself */
int kill_child(unsigned long pid, wzd_context_t * context)
{
  int found=0;
  int i;
  int ret;

#if defined(WZD_MULTIPROCESS)
  /* preliminary check: i can't kill myself */
  if (pid==getpid()) return 1;

  /* checks that pid is really one of the users */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) { found = 1; break; }
  }
  if (!found) return -1;

  ret = kill(pid,SIGTERM);

#elif defined(WZD_MULTITHREAD)

  /* preliminary check: i can't kill myself */
  if (pid==context->pid_child) return 1;

  /* checks that pid is really one of the users */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) { found = 1; break; }
  }
  if (!found) return -1;

#ifdef _MSC_VER
  /* \todo XXX FIXME remove/fix test !! */
  context_list[i].exitclient = 1;
/*  ret = TerminateThread((HANDLE)pid,0);*/
#else
  ret = pthread_cancel(pid);
#endif

#elif
#endif
  return 0;
}

uid_t get_server_uid(void)
{
#ifndef _MSC_VER
  return getuid(); 
#else
  return GetCurrentProcessId();
#endif
}

void server_crashed(int signum)
{
  printf("Server has crashed of signal %d\n",signum);
#ifdef DEBUG
  printf("I'll try to dump current memory to a core file (in the current dir)\n");
  printf("To use this core file you need to run:\n");
  printf("  gdb wzdftpd -core=core_file\n");
  printf("When prompted type be following command:\n");
  printf("  bt\n");
  abort();
#endif
}

/************************************************************************/
/*********************** SERVER MAIN THREAD *****************************/
/************************************************************************/

void serverMainThreadProc(void *arg)
{
  int ret;
  fd_set r_fds, w_fds, e_fds;
  int maxfd;
  struct timeval tv;
  int i;
  unsigned int length=0, size_context, size_user, size_group;
  int backend_storage;
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  WSADATA wsaData;
  int nCode;
#endif

#ifndef _MSC_VER
  /* catch broken pipe ! */
#ifdef __SVR4
  sigignore(SIGPIPE);
  sigset(SIGCHLD,cleanchild);
#else
  signal(SIGPIPE,SIG_IGN);
#ifndef WZD_MULTITHREAD
  signal(SIGCHLD,cleanchild);
#endif /* WZD_MULTITHREAD */
#endif
#endif /* _MSC_VER */

  signal(SIGINT,interrupt);
  signal(SIGTERM,interrupt);
#ifndef _MSC_VER
  signal(SIGKILL,interrupt);

  signal(SIGHUP,server_restart);
#endif

#if defined(POSIX) && ! defined(BSD) /* NO, winblows is NOT posix ! */
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

#if defined(_MSC_VER)
  /* Start Winsock up */
  if ((nCode = WSAStartup(MAKEWORD(2, 0), &wsaData)) != 0) {
    out_log(LEVEL_CRITICAL,"Error initializing winsock2 %s:%d\n",
      __FILE__, __LINE__);
    exit(-1);
  }
#endif

  ret = mainConfig->mainSocket = socket_make((const char *)mainConfig->ip,&mainConfig->port,mainConfig->max_threads);
  if (ret == -1) {
    out_log(LEVEL_CRITICAL,"Error creating socket %s:%d\n",
      __FILE__, __LINE__);
    out_err(LEVEL_CRITICAL,"Could not create main socket - check log for more infos\n");
    /* TODO XXX FIXME we should not exit like this, for at this point context_list
     * and limiter_sem are not allocated ... juste clean up config, but be carefull
     * another instance is not just runnning
     */
    module_free(&mainConfig->module);
    free_config(mainConfig);
    exit(-1);
  }
  FD_REGISTER(ret,"Server listening socket");
  {
    int one=1;

    if (setsockopt(ret, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
      out_log(LEVEL_CRITICAL,"setsockopt(SO_KEEPALIVE");
      /* TODO XXX FIXME we should not exit like this, for at this point context_list
       * and limiter_sem are not allocated ... juste clean up config, but be carefull
       * another instance is not just runnning
       */
      close(ret);
      free_config(mainConfig);
      exit(-1);
    }
  }

#if 0
  /* set up control named pipe */
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

    CloseHandle(hpipe);
  }
#endif /* _MSC_VER */
#endif

#ifndef WIN32
  /* if running as root, we must give up root rigths for security */
  {
    /* effective uid if 0 if run as root or setuid */
    if (geteuid() == 0) {
      out_log(LEVEL_INFO,"Giving up root rights for user %ld (current uid %ld)\n",getlib_server_uid(),getuid());
      setuid(getlib_server_uid());
    }
  }
#endif /* __CYGWIN__ */

  /* creates pid file */
  {
    int fd;
    char buf[64];
#ifndef _MSC_VER
    fd = open(mainConfig->pid_file,O_WRONLY | O_CREAT | O_EXCL,0644);
#else
    /* ignore if file exists for visual version ... */
    fd = open(mainConfig->pid_file,O_WRONLY | O_CREAT,0644);
#endif
    snprintf(buf,64,"%ld\n\0",(unsigned long)getpid());
    if (fd==-1) {
      out_err(LEVEL_CRITICAL,"Unable to open pid file %s: %s\n",mainConfig->pid_file,strerror(errno));
      if (created_shm) {
        free_config(mainConfig);
      }
      exit(1);
    }
    ret = write(fd,buf,strlen(buf));
    close(fd);
  }

/*  context_list = malloc(HARD_USERLIMIT*sizeof(wzd_context_t));*/ /* FIXME 256 */
  size_context = HARD_USERLIMIT*sizeof(wzd_context_t);
  size_user = HARD_DEF_USER_MAX*sizeof(wzd_user_t);
  size_group = HARD_DEF_GROUP_MAX*sizeof(wzd_group_t);
  length = size_context + size_user + size_group;
  context_shm = wzd_shm_create(mainConfig->shm_key,length,0);
  if (context_shm == NULL) {
    out_log(LEVEL_CRITICAL,"Could not get share memory with key 0x%lx - check your config file\n",mainConfig->shm_key);
    exit(1);
  }
  context_list = context_shm->datazone;
  for (i=0; i<HARD_USERLIMIT; i++) {
    context_init(context_list+i);
  }
#ifndef _MSC_VER
  mainConfig->user_list = (void*)((char*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t));
  mainConfig->group_list = (void*)((char*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t)) + (HARD_DEF_USER_MAX*sizeof(wzd_user_t));
#else
  mainConfig->user_list = (wzd_user_t*)((char*)context_list + size_context);
  mainConfig->group_list = (wzd_group_t*)((char*)context_list + size_context + size_user);
#endif

#ifdef WIN32
  /* cygwin sux ... shared library variables are NOT set correctly
   * on dlopenín'
   * remember me to slap the one who told me to make this prog portable ... oops
   * it's me °_°
   */
  setlib_mainConfig(mainConfig);
  setlib_contextList(context_list);
#endif /* WIN32 */

  /* create limiter sem */
  limiter_sem = wzd_sem_create(mainConfig->shm_key+1,1,0);

  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (mainConfig->backend.name[0] == '\0') {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    serverMainThreadExit(-1);
  }
  ret = backend_init(mainConfig->backend.name,&backend_storage,mainConfig->user_list,HARD_DEF_USER_MAX,
      mainConfig->group_list,HARD_DEF_GROUP_MAX);
  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (ret || mainConfig->backend.handle == NULL) {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    serverMainThreadExit(-1);
  }

  /* clear ident list */
  server_ident_list[0] = -1;
  server_ident_list[1] = -1;
  server_ident_list[2] = -1;

  /********* set up functions *******/
  if (command_list_init(&(mainConfig->command_list))) {
    out_log(LEVEL_HIGH,"Could not set up functions\n");
  }

  /****** set up site functions *****/
  if (site_init(mainConfig)) {
    out_log(LEVEL_HIGH,"Could not set up SITE functions\n");
  }

  /********** set up crontab ********/
  cronjob_add(&crontab,check_server_dynamic_ip,"fn:check_server_dynamic_ip",HARD_DYNAMIC_IP_INTVL,
      "*","*","*","*");
  cronjob_add(&crontab,commit_backend,"fn:commit_backend",HARD_COMMIT_BACKEND_INTVL,
      "*","*","*","*");

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

  out_log(LEVEL_INFO,"Process %d ok\n",getpid());

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
    FD_SET(mainConfig->mainSocket,&r_fds);
    FD_SET(mainConfig->mainSocket,&e_fds);
    tv.tv_sec = HARD_REACTION_TIME; tv.tv_usec = 0;
    maxfd = mainConfig->mainSocket;
    server_ident_select(&r_fds, &w_fds, &e_fds, &maxfd);
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    ret = select(0, &r_fds, &w_fds, &e_fds, &tv);
#else
    ret = select(maxfd+1, &r_fds, &w_fds, &e_fds, &tv);
#endif

    time (&server_time);
/*    out_err(LEVEL_FLOOD,".");*/
/*    fflush(stderr);*/
    
    switch (ret) {
    case -1: /* error */
      if (errno == EINTR) continue; /* retry */
      if (errno == EBADF) {
        out_log(LEVEL_CRITICAL,"Bad file descriptor %d\n",
            mainConfig->mainSocket);
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
      server_ident_check(&r_fds,&w_fds,&e_fds);
      /* check ident timeout */
      server_ident_timeout_check();
      if (FD_ISSET(mainConfig->mainSocket,&r_fds)) {
        if (server_add_ident_candidate(mainConfig->mainSocket)) {
          out_log(LEVEL_NORMAL,"could not add connection for ident (%s) :%s:%d\n",
              strerror(errno), __FILE__, __LINE__);
          continue; /* possible cause of error: global ip rejected */
/*          serverMainThreadExit(-1);*/
          /* we abort, so we never returns */
        }
        mainConfig->stats.num_connections++;
      }
    }

    /* check cron jobs */
    cronjob_run(&crontab);

  } /* while (!serverstop) */


  /* commit backend changes */
  ret = backend_commit_changes(mainConfig->backend.name);
  if (ret) {
    out_log(LEVEL_CRITICAL,"Could not commit changes to backend !\n");
  } else
    out_log(LEVEL_INFO,"Backend commited\n");
  serverMainThreadExit(0);
}

static void free_config(wzd_config_t * config)
{
/*  limiter_free(mainConfig->limiter_ul);
  limiter_free(mainConfig->limiter_dl);*/

  ip_free(mainConfig->login_pre_ip_allowed);

  ip_free(mainConfig->login_pre_ip_denied);

  if (mainConfig->xferlog_fd != -1)
    xferlog_close(mainConfig->xferlog_fd);
  if (mainConfig->xferlog_name)
    wzd_free(mainConfig->xferlog_name);
  if (CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG)) {
#ifndef _MSC_VER
    closelog();
#endif
  }
  if (mainConfig->logfile)
    log_close();
  if (mainConfig->logfilename)
    wzd_free(mainConfig->logfilename);
  if (mainConfig->config_filename)
    wzd_free(mainConfig->config_filename);
  if (mainConfig->pid_file)
    wzd_free(mainConfig->pid_file);
  wzd_shm_free(mainConfig_shm);
#ifdef DEBUG
  mainConfig_shm = NULL;
#endif
}

void serverMainThreadExit(int retcode)
{
  out_log(LEVEL_HIGH,"Server exiting, retcode %d\n",retcode);

  /* ignore standard signals from now, we are exiting */
#ifndef _MSC_VER
  signal(SIGINT,SIG_IGN);
#endif
  
  close(mainConfig->mainSocket);
  FD_UNREGISTER(mainConfig->mainSocket,"Server listening socket");
#ifdef WZD_MULTITHREAD
#ifndef _MSC_VER
  /* kill all childs threads */
  if (context_list)
  {
    int i;
    int ret;
    for (i=0; i<HARD_USERLIMIT; i++)
    {
      if (context_list[i].magic == CONTEXT_MAGIC) {
        ret = pthread_cancel(context_list[i].pid_child);
#ifdef DEBUG
        fprintf(stderr,"Killing child %lu - returned %d\n",context_list[i].pid_child,ret);
#endif
/*	client_die(&context_list[i]);*/

#ifdef HAVE_OPENSSL
/*	tls_free(&context_list[i]);*/
#endif
      }
    }
  }
#endif /* _MSC_VER */
#endif
  /* we need to wait for child threads to be effectively dead */
#ifndef _MSC_VER
  sleep(1);
#else
  Sleep(1000);
#endif
#ifdef HAVE_OPENSSL
  tls_exit();
#endif
  wzd_cache_purge();
  server_clear_param(&mainConfig->param_list);
  hook_free(&mainConfig->hook);
  hook_free_protocols();
  module_free(&mainConfig->module);
  backend_close(mainConfig->backend.name);
  cronjob_free(&crontab);
  section_free(&mainConfig->section_list);
  vfs_free(&mainConfig->vfs);
  perm_free_recursive(mainConfig->perm_list);
  site_cleanup(mainConfig);
  command_list_cleanup(&mainConfig->command_list);
  free_messages();
/*  free(context_list);*/
  /* FIXME should not be done here */
  if (mainConfig->backend.param) wzd_free(mainConfig->backend.param);
  wzd_sem_destroy(limiter_sem);
  wzd_shm_free(context_shm);
  context_list = NULL;

  wzd_debug_fini();

  /* free(mainConfig); */
  unlink(mainConfig->pid_file);
  free_config(mainConfig);
#if defined(_MSC_VER)
  WSACleanup();
#endif

#ifdef DEBUG
  /* reset color, there can be some bad control codes ... */
  fprintf(stdout,"%s",CLR_NOCOLOR);
  fprintf(stderr,"%s",CLR_NOCOLOR);
#endif
  exit (retcode);
}
