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

#ifndef __WZD_STRUCTS__
#define __WZD_STRUCTS__

/** \file wzd_structs.h
 * \brief Essential structures
 *
 * \addtogroup libwzd_core
 * @{
 */

#include "wzd_hardlimits.h"

#include "wzd_types.h"

/****************** PRE DECLARATIONS **********************/

typedef struct wzd_backend_t wzd_backend_t;
typedef struct wzd_backend_def_t wzd_backend_def_t;

typedef struct wzd_config_t wzd_config_t;

/*********************** ERRORS ***************************/

typedef enum {
  E_OK=0,

  E_NO_DATA_CTX,	/**< no data connection available */

  E_PARAM_NULL,		/**< parameter is NULL */
  E_PARAM_BIG,		/**< parameter is too long */
  E_PARAM_INVALID,	/**< parameter is invalid */

  E_WRONGPATH,		/**< path is invalid */

  E_NOTDIR,		/**< not a directory */
  E_ISDIR,		/**< is a directory */

  E_NOPERM,		/**< not enough perms */

  E_TIMEOUT,		/**< timeout on control connection */
  E_DATATIMEOUT,	/**< timeout on data connection */
  E_CONNECTTIMEOUT,	/**< timeout on connect() */
  E_PASV_FAILED,	/**< pasv connection failed */
  E_PORT_INVALIDIP,	/**< invalid address in PORT */
  E_XFER_PROGRESS,	/**< transfer in progress */
  E_XFER_REJECTED,	/**< transfer explicitely rejected by, for ex., script */

  E_CREDS_INSUFF,	/**< insufficient credits */

  E_USER_REJECTED,	/**< user rejected */
  E_USER_NO_HOME,	/**< user has no homedir */
  E_USER_NOIP,		/**< ip not allowed */
  E_USER_MAXUSERIP,	/**< max number of ip reached for user */
  E_USER_MAXGROUPIP,	/**< max number of ip reached for group */
  E_USER_CLOSED,	/**< site is closed for this login */
  E_USER_DELETED,	/**< user have been deleted */
  E_USER_NUMLOGINS,	/**< user has reached user num_logins limit */
  E_USER_TLSFORCED,	/**< user must be in TLS mode */

  E_GROUP_NUMLOGINS,	/**< user has reached group num_logins limit */

  E_PASS_REJECTED,	/**< wrong pass */

  E_FILE_NOEXIST,	/**< file does not exist */
  E_FILE_FORBIDDEN,	/**< access to file is forbidden */
  E_FILE_TYPE,	        /**< file has wrong type for operation */

  E_USER_IDONTEXIST,	/**< server said i don't exist ! */
  E_USER_ICANTSUICIDE,	/**< user is trying to kill its connection ! */
  E_USER_NOBODY,	/**< no user was matched by action */

  E_MKDIR_PARSE,	/**< directory name parsing gives errors */
  E_MKDIR_PATHFILTER,	/**< dirname rejected by pathfilter */

  E_COMMAND_FAILED,     /**< system command failed, check errno */


  E_NOMEM,              /**< could not allocate memory */
} wzd_errno_t;

/*********************** RIGHTS ***************************/

#define RIGHT_NONE      0x00000000

#define RIGHT_LIST      0x00000001
#define RIGHT_RETR      0x00000002
#define RIGHT_STOR      0x00000004

#define RIGHT_DELE      0x00000010


/* other rights - should not be used directly ! */
#define RIGHT_CWD       0x00010000
#define RIGHT_MKDIR     0x00020000
#define RIGHT_RMDIR     0x00040000
#define RIGHT_RNFR      0x00200000

typedef unsigned long wzd_perm_t;

/******************** BANDWIDTH LIMIT *********************/

/** @brief Limit bandwidth
 */
typedef struct limiter
{
  u32_t maxspeed;
#ifndef WIN32
  struct timeval current_time;
#else
  struct _timeb current_time;
#endif
  int bytes_transfered;
  float current_speed;
} wzd_bw_limiter;

/*********************** SITE *****************************/

/* opaque struct */
typedef struct wzd_site_fct_t wzd_site_fct_t;

/********************* IP CHECKING ************************/
typedef struct _wzd_ip_list_t {
  char  * regexp;
  u8_t  is_allowed;
  struct _wzd_ip_list_t * next_ip;
} wzd_ip_list_t;

/************************ VFS *****************************/
typedef struct _wzd_vfs_t {
  char	* virtual_dir;
  char	* physical_dir;

  char	* target;

  struct _wzd_vfs_t	* prev_vfs, * next_vfs;
} wzd_vfs_t;

/*********************** DATA *****************************/
typedef enum {
  DATA_PORT,
  DATA_PASV
} data_mode_t;

/*********************** STATS ****************************/
/** @brief User statistics: number of files downloaded, etc
 */
typedef struct {
  u64_t             bytes_ul_total;
  u64_t             bytes_dl_total;
  unsigned long		files_ul_total;
  unsigned long		files_dl_total;
} wzd_stats_t;

/********************** USER, GROUP ***********************/

typedef struct wzd_user_t wzd_user_t;

typedef struct wzd_group_t wzd_group_t;

/*********************** BACKEND **************************/

/** IMPORTANT:
 *
 * all validation functions have the following return code:
 *
 *   0 = success
 *
 *   !0 = failure
 *
 * the last parameter of all functions is a ptr to current user
 */


struct wzd_backend_def_t {
  char * filename;

  char * param;
  void * handle;

  struct wzd_backend_t * b;
};


/************************ FLAGS ***************************/

enum wzd_flag_t {
  FLAG_ANONYMOUS = 'A', /**< anonymous users cannot modify filesystem */
  FLAG_DELETED = 'D',
  FLAG_FULLPATH = 'f',  /**< show the complete path to the user */
  FLAG_GADMIN = 'G',
  FLAG_HIDDEN = 'H',
  FLAG_ULTRAHIDDEN = 'h',
  FLAG_IDLE = 'I',
  FLAG_TLS = 'k',       /**< explicit and implicit connections only */
  FLAG_TLS_DATA = 'K',  /**< user must use encrypted data connection */
  FLAG_SITEOP = 'O',
  FLAG_SEE_IP = 's',
  FLAG_SEE_HOME = 't',
  FLAG_COLOR = '5',     /**< enable use of colors */
};

/************************ MODULES *************************/

typedef int (*void_fct)(void);

typedef struct _wzd_hook_t {
  unsigned long mask;

  char *	opt;	/* used by custom site commands */

  void_fct	hook;
  char *	external_command;

  struct _wzd_hook_t	*next_hook;
} wzd_hook_t;

typedef struct _wzd_module_t {
  char *	name;

  void *	handle;

  struct _wzd_module_t	*next_module;
} wzd_module_t;

/* defined in binary, combine with OR (|) */

/* see also event_tab[] in wzd_mod.c */

enum event_id_t {
  EVENT_NONE          = 0x00000000,

  EVENT_LOGIN         = 0x00000001,
  EVENT_LOGOUT        = 0x00000002,

  EVENT_PREUPLOAD     = 0x00000010,
  EVENT_POSTUPLOAD    = 0x00000020,
  EVENT_PREDOWNLOAD   = 0x00000040,
  EVENT_POSTDOWNLOAD  = 0x00000080,

  EVENT_PREMKDIR      = 0x00000100,
  EVENT_MKDIR         = 0x00000200,
  EVENT_PRERMDIR      = 0x00000400,
  EVENT_RMDIR         = 0x00000800,

  EVENT_PREDELE       = 0x00004000,
  EVENT_DELE          = 0x00008000,

  EVENT_SITE          = 0x00010000,
  EVENT_CRONTAB       = 0x00100000,

};

/************************ SECTIONS ************************/

typedef struct wzd_section_t wzd_section_t;
/** @brief Section: definition, properties */
struct wzd_section_t {
  char *        sectionname;
  char *        sectionmask;
  char *        sectionre;

/*  regex_t *	pathfilter;*/
  void *	pathfilter;

  struct wzd_section_t * next_section;
};

/********************** SERVER STATS **********************/

/** @brief Server statistics: number of connections, etc */
typedef struct {
  unsigned long num_connections; /**< @brief total # of connections since server start */
  unsigned long num_childs; /**< @brief total # of childs process created since server start */
} wzd_server_stat_t;

/********************** SERVER PARAMS *********************/

/** @brief Server parameters: stored in server global memory space,
 * accessible to every thread.
 */
typedef struct _wzd_param_t {
  char * name;
  void * param;
  unsigned int length;

  struct _wzd_param_t	* next_param;
} wzd_param_t;

/*************************** IP **************************/

#include "wzd_ip.h"

/*************************** TLS **************************/

#ifndef HAVE_OPENSSL
# define SSL     void
# define SSL_CTX void
#else
# include <openssl/ssl.h>
# include <openssl/rand.h>
# include <openssl/err.h>
#endif

typedef enum { TLS_CLEAR, TLS_PRIV } ssl_data_t; /* data modes */

typedef enum { TLS_SERVER_MODE=0, TLS_CLIENT_MODE } tls_role_t;

typedef enum { TLS_NOTYPE=0, TLS_EXPLICIT, TLS_STRICT_EXPLICIT, TLS_IMPLICIT } tls_type_t;

typedef enum { TLS_NONE, TLS_READ, TLS_WRITE } ssl_fd_mode_t;

/** @brief SSL connection objects */
typedef struct {
  SSL *         obj;
  ssl_data_t    data_mode;
  SSL *         data_ssl;
  ssl_fd_mode_t ssl_fd_mode;
} wzd_ssl_t;

typedef struct {
  void * session;
  void * data_session;
} wzd_tls_t;

typedef enum {
  ASCII=0,
  BINARY
} xfer_t;

/************************* CONTEXT ************************/

/** important - must not be fffff or d0d0d0, etc.
 * to make distinction with unallocated zone
 */
#define	CONTEXT_MAGIC	0x0aa87d45

/** context::connection_flags field */
#define	CONNECTION_TLS	0x00000040
#define	CONNECTION_UTF8	0x00000100

typedef int (*read_fct_t)(fd_t,char*,size_t,int,unsigned int,void *);
typedef int (*write_fct_t)(fd_t,const char*,size_t,int,unsigned int,void *);

typedef struct wzd_context_t wzd_context_t;

#include "wzd_action.h"

/** @brief Connection state
 */
typedef enum {
  STATE_UNKNOWN=0,
  STATE_CONNECTING, /* waiting for ident */
  STATE_LOGGING,
  STATE_COMMAND,
  STATE_XFER
} connection_state_t;

/** @brief Client-specific data
 */
struct wzd_context_t {
  unsigned long	magic;  /**< \brief magic number, used to test structure integrity */

  net_family_t  family; /**< \brief IPv4 or IPv6 */
  unsigned char	hostip[16];
  wzd_ip_t      * peer_ip;
  char          * ident;
  connection_state_t state;
  unsigned char	exitclient;
  fd_t          controlfd;
  fd_t          datafd;
  data_mode_t   datamode;
  net_family_t  datafamily; /**< \brief IPv4 or IPv6 */
  unsigned long	pid_child;
  unsigned long	thread_id;

  fd_t          pasvsock;
  read_fct_t    read_fct;
  write_fct_t   write_fct;
  int           dataport;
  unsigned char dataip[16];
  u64_t         resume;
  unsigned long	connection_flags;
  char          currentpath[WZD_MAX_PATH];
  u32_t 	userid;
  xfer_t        current_xfer_type;
  wzd_action_t	current_action;
  struct last_file_t	last_file;
  char          * data_buffer;
/*  wzd_bw_limiter * current_limiter;*/
  wzd_bw_limiter current_ul_limiter;
  wzd_bw_limiter current_dl_limiter;
  time_t        login_time;
  time_t	idle_time_start;
  time_t	idle_time_data_start;
  wzd_ssl_t   	ssl;
  wzd_tls_t   	tls;
  tls_role_t    tls_role; /**< \brief TLS role: server or client */
  struct _auth_gssapi_data_t * gssapi_data;
};

/********************** COMMANDS **************************/

#include "wzd_commands.h"

/************************ MAIN CONFIG *********************/

#include "wzd_backend.h"

/* macros used with options */
#define CFG_OPT_DENY_ACCESS_FILES_UPLOADED  0x00000001
#define CFG_OPT_HIDE_DOTTED_FILES           0x00000002
#define CFG_OPT_USE_SYSLOG                  0x00000010
#define CFG_OPT_DISABLE_TLS                 0x00000100
#define CFG_OPT_DISABLE_IDENT               0x00000200
#define CFG_OPT_UTF8_CAPABLE                0x00001000
#define CFG_OPT_CHECKIP_LOGIN               0x00010000
#define CFG_OPT_REJECT_UNKNOWN_USERS        0x00020000
#define CFG_OPT_DYNAMIC_IP                  0x00100000


#define CFG_CLR_OPTION(c,opt)   (c)->server_opts &= ~(opt)
#define CFG_SET_OPTION(c,opt)   (c)->server_opts |= (opt)
#define CFG_GET_OPTION(c,opt)   ( (c)->server_opts & (opt) )

/** @brief Server config
 *
 * Contains all variables specific to a server instance.
 */
struct wzd_config_t {
  char *	pid_file;
  char *	config_filename;
  time_t	server_start;
  unsigned char	serverstop;
  unsigned char	site_closed;
  wzd_backend_def_t	backend;
  int		max_threads;
  char *	logfilename;
  unsigned int	logfilemode;
  FILE *	logfile;
  char *	xferlog_name;
  int		xferlog_fd;
  int		loglevel;
  char *        logdir;
  unsigned int  umask;
  char *	dir_message;
  fd_t		controlfd; /**< external control: named pipe, unix socket, or socket */
  char          ip[MAX_IP_LENGTH];
  char          dynamic_ip[MAX_IP_LENGTH];
  unsigned int	port;
  u32_t         pasv_low_range;
  u32_t         pasv_high_range;
  unsigned char	pasv_ip[16];
  wzd_ip_list_t	*login_pre_ip_checks;
  wzd_vfs_t	*vfs;
  wzd_hook_t	*hook;
  wzd_module_t	*module;
  unsigned int  data_buffer_length; /**< size of buffer used for transfers. This has a great impact on performances */
  unsigned long	server_opts;
  wzd_server_stat_t	stats;
  SSL_CTX *	tls_ctx;
  tls_type_t	tls_type;
  CHTBL          * commands_list;
  wzd_site_fct_t	* site_list;
  wzd_section_t		* section_list;
  wzd_param_t		* param_list;

  wzd_bw_limiter	global_ul_limiter;
  wzd_bw_limiter	global_dl_limiter;

  struct _wzd_configfile_t * cfg_file;

  struct wzd_cronjob_t * crontab;

  struct wzd_event_manager_t * event_mgr;
};

WZDIMPORT extern wzd_config_t *	mainConfig;
WZDIMPORT extern List * context_list;

/************************ LIST ****************************/

enum list_type_t {
  LIST_TYPE_NONE   = 0,
  LIST_TYPE_SHORT  = 1 << 0,
  LIST_TYPE_LONG   = 1 << 1,
  LIST_SHOW_HIDDEN = 1 << 2,
};

/** @} */

#endif /* __WZD_STRUCTS__ */
