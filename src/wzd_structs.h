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

#ifndef __WZD_STRUCTS__
#define __WZD_STRUCTS__

#include "wzd_hardlimits.h"

/*********************** RIGHTS ***************************/

#define RIGHT_NONE      0x00000000

#define RIGHT_LIST      0x00000001
#define RIGHT_RETR      0x00000002
#define RIGHT_STOR      0x00000004


/* other rights - should not be used directly ! */
#define RIGHT_CWD       0x00010000
#define RIGHT_MKDIR     0x00020000
#define RIGHT_RMDIR     0x00040000
#define RIGHT_RNFR      0x00200000

typedef unsigned long wzd_perm_t;

/******************** BANDWIDTH LIMIT *********************/

typedef struct limiter
{
  int maxspeed;
  struct timeval current_time;
  int bytes_transfered;
  float current_speed;
} wzd_bw_limiter;

/**************** COMMANDS PERMISSIONS ********************/
typedef enum {
  CP_USER,
  CP_GROUP,
  CP_FLAG
} wzd_cp_t;

/* opaque struct */
typedef struct wzd_command_perm_entry_t wzd_command_perm_entry_t;
typedef struct wzd_command_perm_t wzd_command_perm_t;

/*********************** SITE *****************************/
typedef struct {
  char	file_ginfo[256];
  char	file_group[256];
  char	file_help[256];
  char	file_rules[256];
  char	file_swho[256];
  char	file_user[256];
  char	file_users[256];
  char	file_who[256];
} wzd_site_config_t;

/* opaque struct */
typedef struct wzd_site_fct_t wzd_site_fct_t;

/********************* IP CHECKING ************************/
typedef struct _wzd_ip_t {
  char  * regexp;
  struct _wzd_ip_t * next_ip;
} wzd_ip_t;

/************************ VFS *****************************/
typedef struct _wzd_vfs_t {
  char	* virtual_dir;
  char	* physical_dir;

  char	* target;

  struct _wzd_vfs_t	* next_vfs;
} wzd_vfs_t;

/*********************** DATA *****************************/
typedef enum {
  DATA_PORT,
  DATA_PASV
} data_mode_t;

/********************** USER, GROUP ***********************/

typedef struct {
  char                  username[HARD_USERNAME_LENGTH];
  char			userpass[256];
  char                  rootpath[1024];
  char                  tagline[256];
  unsigned int          uid;
  unsigned int          group_num;
  unsigned int          groups[256];
  time_t	        max_idle_time;
  wzd_perm_t            userperms;
  char                  flags[MAX_FLAGS_NUM];
  unsigned long         max_ul_speed;
  unsigned long         max_dl_speed;   /**< bytes / sec */
  unsigned short	num_logins;	/**< number of simultaneous logins allowed */
  char			ip_allowed[HARD_IP_PER_USER][MAX_IP_LENGTH];
  unsigned long long	bytes_ul_total;
  unsigned long long	bytes_dl_total;
  unsigned long		files_ul_total;
  unsigned long		files_dl_total;
  unsigned long long	credits;
  unsigned int		ratio;
  unsigned short	user_slots;	/**< user slots for gadmins */
  unsigned short	leech_slots;	/**< leech slots for gadmins */
  time_t		last_login;
} wzd_user_t;

typedef struct {
  char                  groupname[128];
  wzd_perm_t            groupperms;
  time_t		max_idle_time;
  unsigned long         max_ul_speed;
  unsigned long         max_dl_speed;
  unsigned int		ratio;
  char			ip_allowed[HARD_IP_PER_GROUP][MAX_IP_LENGTH];
  char			defaultpath[1024];
} wzd_group_t;

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


typedef struct {
  char name[HARD_BACKEND_NAME_LENGTH];
  void * param;
  void * handle;
  int backend_storage;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
  int (*back_find_user) (const char *, wzd_user_t *);
  int (*back_find_group) (int, wzd_group_t *);
  int (*back_chpass) (const char *, const char *);
  int (*back_mod_user) (const char *, wzd_user_t *, unsigned long);
  int (*back_mod_group) (const char *, wzd_group_t *, unsigned long);
  int (*back_commit_changes) (void);
} wzd_backend_t;


/************************ FLAGS ***************************/

#define	FLAG_SITEOP	'O'
#define	FLAG_DELETED	'D'
#define	FLAG_IDLE	'I'
#define	FLAG_SEE_IP	's'
#define	FLAG_SEE_HOME	't'
#define	FLAG_HIDDEN	'H'
#define	FLAG_GADMIN	'G'
#define	FLAG_TLS	'k'	/* explicit and implicit connections only */
#define	FLAG_ANONYMOUS	'A'	/* anonymous users cannot modify filesystem */

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

#define	EVENT_LOGIN		0x00000001
#define	EVENT_LOGOUT		0x00000002

#define	EVENT_PREUPLOAD		0x00000010
#define	EVENT_POSTUPLOAD	0x00000020
#define	EVENT_POSTDOWNLOAD	0x00000080

#define	EVENT_MKDIR		0x00000100
#define	EVENT_RMDIR		0x00000200

#define	EVENT_SITE		0x00010000

/************************ SECTIONS ************************/

/* opaque struct */
typedef struct wzd_section_t wzd_section_t;

/************************** SFV ***************************/

/* values randomly chosen :) */ 
#define	SFV_UNKNOWN	0x0324
#define	SFV_OK		0x7040
#define	SFV_MISSING	0x0220
#define	SFV_BAD		0x1111

typedef struct {
  char *        filename;
  unsigned long crc;
  unsigned int	state;
  unsigned long	size;
} wzd_sfv_entry;

typedef struct {
  char **       comments;
  wzd_sfv_entry **sfv_list;
} wzd_sfv_file;

/********************** SERVER STATS **********************/

typedef struct {
  unsigned long num_connections; /**< total # of connections since server start */
  unsigned long num_childs; /**< total # of childs process created since server start */
} wzd_server_stat_t;

/*************************** TLS **************************/

#ifndef SSL_SUPPORT
#define SSL     void
#define SSL_CTX void
#endif

typedef enum { TLS_CLEAR, TLS_PRIV} ssl_data_t; /* data modes */

typedef enum { TLS_NOTYPE=0, TLS_EXPLICIT, TLS_STRICT_EXPLICIT, TLS_IMPLICIT} tls_type_t; 

typedef enum { TLS_NONE, TLS_READ, TLS_WRITE} ssl_fd_mode_t; 

typedef struct {
  char          certificate[256];
  SSL *         obj;
  ssl_data_t    data_mode;
  SSL *         data_ssl;
  ssl_fd_mode_t ssl_fd_mode;
} wzd_ssl_t;

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

typedef int (*read_fct_t)(int,char*,unsigned int,int,int,void *);
typedef int (*write_fct_t)(int,const char*,unsigned int,int,int,void *);

#include "wzd_action.h"

typedef struct {
  unsigned long	magic;
  unsigned char	hostip[4];
  int           state;
  int           controlfd;
  int           datafd;
  data_mode_t   datamode;
  unsigned long	pid_child;
  int	        portsock;
  int	        pasvsock;
  read_fct_t	read_fct;
  write_fct_t	write_fct;
  int	        dataport;
  int	        dataip[4];
  unsigned long	resume;
  unsigned long	connection_flags;
  char          currentpath[2048];
/*  wzd_user_t    userinfo;*/
  unsigned int	userid;
  xfer_t        current_xfer_type;
  wzd_action_t	current_action;
  char		last_command[HARD_LAST_COMMAND_LENGTH];
/*  wzd_bw_limiter * current_limiter;*/
  wzd_bw_limiter current_ul_limiter;
  wzd_bw_limiter current_dl_limiter;
  time_t	idle_time_start;
  time_t	idle_time_data_start;
  wzd_ssl_t   	ssl;
} wzd_context_t;

/************************ MAIN CONFIG *********************/

#include "wzd_backend.h"

/* macros used with options */
#define	CFG_OPT_DENY_ACCESS_FILES_UPLOADED	0x00000001

#define	CFG_CLEAR_DENY_ACCESS_FILES_UPLOADED(c)	(c)->server_opts &= ~CFG_OPT_DENY_ACCESS_FILES_UPLOADED

#define	CFG_SET_DENY_ACCESS_FILES_UPLOADED(c)	(c)->server_opts |= CFG_OPT_DENY_ACCESS_FILES_UPLOADED

#define	CFG_GET_DENY_ACCESS_FILES_UPLOADED(c)	( (c)->server_opts & CFG_OPT_DENY_ACCESS_FILES_UPLOADED )

typedef struct {
  char *	config_filename;
  time_t	server_start;
  unsigned char	serverstop;
  unsigned char	site_closed;
  wzd_backend_t	backend;
  int		max_threads;
  char *	logfilename;
  unsigned int	logfilemode;
  FILE *	logfile;
  char *	xferlog_name;
  int		xferlog_fd;
  int		loglevel;
  char		dir_message[256]; /** useless */
  int		mainSocket;
  unsigned char	ip[MAX_IP_LENGTH];
  unsigned char	dynamic_ip[MAX_IP_LENGTH];
  unsigned int	port;
  unsigned long	pasv_low_range;
  unsigned long	pasv_high_range;
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
  wzd_site_fct_t	* site_list;
  wzd_section_t		* section_list;
/*  wzd_bw_limiter	* limiter_ul;
  wzd_bw_limiter	* limiter_dl;*/
  wzd_bw_limiter	global_ul_limiter;
  wzd_bw_limiter	global_dl_limiter;
  wzd_site_config_t	site_config;
  wzd_user_t	*user_list;
  wzd_group_t	*group_list;
} wzd_config_t;

#include "wzd_shm.h"

extern wzd_config_t *	mainConfig;
extern wzd_shm_t * 	mainConfig_shm;
extern wzd_context_t *	context_list;

/************************ LIST ****************************/

#define	LIST_TYPE_SHORT		0x0000
#define	LIST_TYPE_LONG		0x0001
#define	LIST_SHOW_HIDDEN	0x0010
typedef unsigned long list_type_t;

/*********************** VERSION **************************/

/* Version */
/*#define	WZD_VERSION_NUM	"0.1rc2"*/

#ifdef WZD_MULTIPROCESS
#define	WZD_MP	" mp "
#else /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
#define	WZD_MP	" mt "
#else
#define	WZD_MP	" up "
#endif /* WZD_MULTITHREAD */
#endif /* WZD_MULTIPROCESS */

#ifdef __CYGWIN__
#define	WZD_VERSION_STR	"wzdFTPd cygwin" WZD_MP WZD_VERSION_NUM
#else /* __CYGWIN__ */
#define	WZD_VERSION_STR	"wzdFTPd linux" WZD_MP WZD_VERSION_NUM
#endif /* __CYGWIN__ */


#endif /* __WZD_STRUCTS__ */
