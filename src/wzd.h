#ifndef __WZD__
#define __WZD__

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
#include <netinet/in.h>
#include <netdb.h>
#define INVALID_SOCKET -1
#define	closesocket close

#if SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* SSL_SUPPORT */

#define Sleep(x)	usleep((x)*1000)

#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>


/* must be first */
#include "wzd_hardlimits.h"
#include "wzd_shm.h"
#include "wzd_structs.h"

#include "wzd_backend.h"

#include "wzd_action.h"
#include "wzd_misc.h"

#if SSL_SUPPORT
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
#endif

typedef enum {
  ASCII=0,
  BINARY
} xfer_t;

typedef enum {
  LIST_TYPE_SHORT=0,
  LIST_TYPE_LONG
} list_type_t;

typedef enum {
  DATA_PORT,
  DATA_PASV
} data_mode_t;

/* important - must not be fffff or d0d0d0, etc.
 * to make distinction with unallocated zone
 */
#define	CONTEXT_MAGIC	0x0aa87d45

typedef struct {
  unsigned long	magic;
  int           state;
  int           controlfd;
  int           datafd;
  data_mode_t   datamode;
  int	        pid_child;
  int	        portsock;
  int	        pasvsock;
  int	        dataport;
  int	        dataip[4];
  unsigned long	resume;
  char          currentpath[2048];
  wzd_user_t    userinfo;
  xfer_t        current_xfer_type;
  wzd_action_t	current_action;
  char		last_command[2048];
  wzd_bw_limiter * current_limiter;
#if SSL_SUPPORT
  wzd_ssl_t   	ssl;
#endif
} wzd_context_t;


void set_action(wzd_context_t * context, unsigned int token, const char *arg);

typedef int (*read_fct_t)(int,char*,unsigned int,int,int,wzd_context_t *);
typedef int (*write_fct_t)(int,const char*,unsigned int,int,int,wzd_context_t *);

typedef struct {
  wzd_backend_t	backend;
  int		max_threads;
  char *	logfilename;
  char *	logfilemode;
  FILE *	logfile;
  int		loglevel;
  read_fct_t	read_fct;
  write_fct_t	write_fct;
  int		mainSocket;
  int		port;
#if SSL_SUPPORT
  char		tls_certificate[256];
  char          tls_cipher_list[256];
  SSL_CTX *	tls_ctx;
  tls_type_t	tls_type;
#endif
  unsigned long	shm_key;
  wzd_command_perm_t	* perm_list;
  wzd_bw_limiter	* limiter_ul;
  wzd_bw_limiter	* limiter_dl;
  wzd_site_config_t	site_config;
} wzd_config_t;

extern wzd_config_t	mainConfig;
extern wzd_context_t *	context_list;


/* DEBUG & LOG */
#define LEVEL_LOWEST	1
#define	LEVEL_FLOOD	1
#define	LEVEL_INFO	3
#define	LEVEL_NORMAL	5
#define	LEVEL_HIGH	7
#define	LEVEL_CRITICAL	9


#include "wzd_tls.h"
#include "wzd_socket.h"
#include "wzd_messages.h"
#include "wzd_log.h"
#include "wzd_file.h"
#include "wzd_init.h"
#include "wzd_data.h"
#include "wzd_perm.h"
#include "wzd_ServerThread.h"
#include "wzd_ClientThread.h"
#include "wzd_site.h"
#include "ls.h"

#endif /* __WZD__ */
