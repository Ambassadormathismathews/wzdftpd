#ifndef __WZD__
#define __WZD__

#define WZD_MULTIPROCESS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define INVALID_SOCKET -1

#if SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* SSL_SUPPORT */

#define Sleep(x)	usleep((x)*1000)

#include <sys/wait.h>
/*define _XOPEN_SOURCE*/
#include <time.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>
#include <dirent.h>

#define	KEY_BELL	"\007"

#if 0
/* colors */

#define CLR_BOLD	"[1m"

#define	CLR_BLUE	"[34m"
#define	CLR_CYAN	"[36m"
#define	CLR_GREEN	"[32m"
#define	CLR_RED		"[31m"

#define	CLR_NOCOLOR	"[0m"
#endif

/* must be first */
#include "wzd_hardlimits.h"
#include "wzd_shm.h"
#include "wzd_structs.h"

#include "wzd_backend.h"

#include "wzd_action.h"
#include "wzd_misc.h"
#include "wzd_cache.h"

#if 0
#if !SSL_SUPPORT
#define	SSL	void
#define	SSL_CTX	void
#endif

typedef enum { TLS_CLEAR, TLS_PRIV } ssl_data_t; /* data modes */

typedef enum { TLS_NOTYPE=0, TLS_EXPLICIT, TLS_STRICT_EXPLICIT, TLS_IMPLICIT } tls_type_t;

typedef enum { TLS_NONE, TLS_READ, TLS_WRITE } ssl_fd_mode_t;

typedef struct {
  char		certificate[256];
  SSL *		obj;
  ssl_data_t	data_mode;
  SSL *		data_ssl;
  ssl_fd_mode_t	ssl_fd_mode;
} wzd_ssl_t;

typedef enum {
  ASCII=0,
  BINARY
} xfer_t;
#endif

#if 0
#define	LIST_TYPE_SHORT		0x0000
#define	LIST_TYPE_LONG		0x0001
#define	LIST_SHOW_HIDDEN	0x0010
typedef unsigned long list_type_t;
#endif

#if 0
/* important - must not be fffff or d0d0d0, etc.
 * to make distinction with unallocated zone
 */
#define	CONTEXT_MAGIC	0x0aa87d45

typedef int (*read_fct_t)(int,char*,unsigned int,int,int,void *);
typedef int (*write_fct_t)(int,const char*,unsigned int,int,int,void *);

typedef struct {
  unsigned long	magic;
  unsigned char	hostip[4];
  int           state;
  int           controlfd;
  int           datafd;
  data_mode_t   datamode;
  int	        pid_child;
  int	        portsock;
  int	        pasvsock;
  read_fct_t	read_fct;
  write_fct_t	write_fct;
  int	        dataport;
  int	        dataip[4];
  unsigned long	resume;
  char          currentpath[2048];
/*  wzd_user_t    userinfo;*/
  unsigned int	userid;
  xfer_t        current_xfer_type;
  wzd_action_t	current_action;
  char		last_command[2048];
/*  wzd_bw_limiter * current_limiter;*/
  wzd_bw_limiter current_ul_limiter;
  wzd_bw_limiter current_dl_limiter;
  time_t	idle_time_start;
  time_t	idle_time_data_start;
  wzd_ssl_t   	ssl;
} wzd_context_t;
#endif


void set_action(wzd_context_t * context, unsigned int token, const char *arg);

#if 0
/* macros used with options */
#define	CFG_OPT_DENY_ACCESS_FILES_UPLOADED	0x00000001

#define	CFG_SET_DENY_ACCESS_FILES_UPLOADED(c)	(c)->server_opts |= CFG_OPT_DENY_ACCESS_FILES_UPLOADED

#define	CFG_GET_DENY_ACCESS_FILES_UPLOADED(c)	( (c)->server_opts & CFG_OPT_DENY_ACCESS_FILES_UPLOADED )

typedef struct {
  int		serverstop;
  wzd_backend_t	backend;
  int		max_threads;
  char *	logfilename;
  char *	logfilemode;
  FILE *	logfile;
  char *	xferlog_name;
  int		xferlog_fd;
  int		loglevel;
  char		messagefile[256]; /* useless */
  int		mainSocket;
  unsigned char	ip[64];
  unsigned char	dynamic_ip[64];
  int		port;
  unsigned long	pasv_low_range;
  unsigned long	pasv_up_range;
  unsigned char	pasv_ip[4];
  int		login_pre_ip_check;
  wzd_ip_t	*login_pre_ip_allowed;
  wzd_ip_t	*login_pre_ip_denied;
  wzd_vfs_t	*vfs;
  wzd_hook_t	*hook;
  wzd_module_t	*module;
  unsigned long	server_opts;
  wzd_server_stat_t	stats;
  char		tls_certificate[256];
  char          tls_cipher_list[256];
  SSL_CTX *	tls_ctx;
  tls_type_t	tls_type;
  unsigned long	shm_key;
  wzd_command_perm_t	* perm_list;
/*  wzd_bw_limiter	* limiter_ul;
  wzd_bw_limiter	* limiter_dl;*/
  wzd_bw_limiter	global_ul_limiter;
  wzd_bw_limiter	global_dl_limiter;
  wzd_site_config_t	site_config;
  wzd_user_t	*user_list;
  wzd_group_t	*group_list;
} wzd_config_t;


extern wzd_config_t *	mainConfig;
extern wzd_shm_t * 	mainConfig_shm;
extern wzd_context_t *	context_list;

#endif

#include "wzd_tls.h"
#include "wzd_socket.h"
#include "wzd_messages.h"
#include "wzd_log.h"
#include "wzd_file.h"
#include "wzd_init.h"
#include "wzd_data.h"
#include "wzd_perm.h"
#include "wzd_mod.h"
#include "wzd_vfs.h"
#if INTERNAL_SFV
#include "wzd_crc32.h"
#endif
#include "wzd_ServerThread.h"
#include "wzd_ClientThread.h"
#include "wzd_site_user.h"
#include "wzd_site.h"
#include "ls.h"

#if 0
/* Version */
/*#define	WZD_VERSION_NUM	"0.1rc2"*/

#ifdef WZD_MULTIPROCESS
#define	WZD_MP	" mp "
#else /* WZD_MULTIPROCESS */
#define	WZD_MP	" up "
#endif /* WZD_MULTIPROCESS */

#ifdef __CYGWIN__
#define	WZD_VERSION_STR	"wzdFTPd cygwin" WZD_MP WZD_VERSION_NUM
#else /* __CYGWIN__ */
#define	WZD_VERSION_STR	"wzdFTPd linux" WZD_MP WZD_VERSION_NUM
#endif /* __CYGWIN__ */
#endif

#include "wzd_libmain.h"

#endif /* __WZD__ */
