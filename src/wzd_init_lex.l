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

/* used to include files */
%x incl

%{
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>	/* gethostbyname() */
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>	/* ULONG_MAX */
#include <signal.h>     /* kill() */

#ifndef WIN32
#include <pwd.h>	/* getpwnam() */
#endif

#include "wzd_structs.h"

#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_libmain.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_perm.h"
#include "wzd_crontab.h"
#include "wzd_section.h"
#include "wzd_ServerThread.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

typedef enum {
  CFG_ID=256,
  CFG_IP_NUM,
  CFG_IP_STR,
  CFG_NUM,
  CFG_EOL,
  CFG_EQUAL,
  CFG_LOWER_EQ,
  CFG_GREATER_EQ,

  CFG_BACKEND,
  CFG_BACKEND_PARAM,
  CFG_CRONJOB,
  CFG_CSCRIPT,
  CFG_DATABUFFER_LENGTH,
  CFG_DENY_ACCESS_FUP,
  CFG_DIR_MESSAGE,
  CFG_DYNAMIC_IP,
  CFG_FORCE_SHM_CLEANUP,
  CFG_HIDE_DOTTED_FILES,
  CFG_INTERNAL_SFV,
  CFG_IP,
  CFG_LOGDIR,
  CFG_LOGFILE,
  CFG_LOGLEVEL,
  CFG_LOG_PRE_CHECK,
  CFG_LOG_PRE_IP_ALLOW,
  CFG_LOG_PRE_IP_DENY,
  CFG_MAX_DL_SPEED,
  CFG_MAX_THREADS,
  CFG_MAX_UL_SPEED,
  CFG_MESSAGE,
  CFG_MODULE,
  CFG_PARAM,
  CFG_PASV_IP,
  CFG_PASV_LOW,
  CFG_PASV_HIGH,
  CFG_PID_FILE,
  CFG_PORT,
  CFG_SECTION,
  CFG_SERVER_UID,
  CFG_SHM_KEY,
  CFG_SITE,
  CFG_SITECMD,
  CFG_SITEFILE,
  CFG_TLS_CERT,
  CFG_TLS_CIPHER_LIST,
  CFG_TLS_MODE,
  CFG_UMASK,
  CFG_USE_SYSLOG,
  CFG_VFS,
  CFG_XFERLOG,

  CFG_UNKNOWN
} wzd_config_token_t;

unsigned int cfg_is_keyword(char *word);

int mylineno=0;

#define	MAX_INCLUDE_DEPTH	10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr=0;

wzd_config_t tempConfig;

extern wzd_cronjob_t * crontab;

%}

DIGIT	[0-9]
LETTER	[a-zA-Z]

COMMENT	#.*$

IP_NUM	{DIGIT}{1,3}"."{DIGIT}{1,3}"."{DIGIT}{1,3}"."{DIGIT}{1,3}
IP_STR	"+"[^ \t\n]+
ID	{LETTER}({LETTER}|{DIGIT}|[_.])*
HEXNUM	"0x"({DIGIT}|[a-fA-F])+
REALNUM	{DIGIT}+("."{DIGIT}+)?
NUM	({HEXNUM}|{REALNUM})

%option nounput
%option	never-interactive
%%

[ \t\r]+	/* skip */
\n		return CFG_EOL;

{COMMENT}	/* ignore */

"=="		return CFG_EQUAL;
"<="		return CFG_LOWER_EQ;
">="		return CFG_GREATER_EQ;

include		BEGIN(incl);

<incl>[ \t]*	/* eat whitespaces */
<incl>[^ \t\n]+	{
			if (include_stack_ptr >= MAX_INCLUDE_DEPTH)
			{
				fprintf(stderr,"Includes nested too deeply\n");
				return -1;
			}
			include_stack[include_stack_ptr++]=YY_CURRENT_BUFFER;
			yyin=fopen(yytext,"r");
			if (!yyin) {
				fprintf(stderr,"File does not exist\n");
				return 1;
			}
			yy_switch_to_buffer(yy_create_buffer(yyin,YY_BUF_SIZE));
			BEGIN(INITIAL);
		}

{IP_NUM}	return CFG_IP_NUM;
{IP_STR}	return CFG_IP_STR;
{ID}		{ unsigned int tok=cfg_is_keyword(yytext); return tok?tok:CFG_ID; }
{NUM}		return CFG_NUM;

<<EOF>>		{
			if (--include_stack_ptr<0)
			{
				yy_delete_buffer(YY_CURRENT_BUFFER);
				yyterminate();
			}
			else
			{
				yy_delete_buffer(YY_CURRENT_BUFFER);
				yy_switch_to_buffer(include_stack[include_stack_ptr]);
			}
		}

.		return *yytext;

%%

unsigned int cfg_is_keyword(char *word)
{
  ascii_lower(word,strlen(word));
  /* order IS important for some keywords (site) */
  if (!strcmp(word,"backend")) return CFG_BACKEND;
  if (!strncmp(word,"backend_param_",strlen("backend_param_")))
    return CFG_BACKEND_PARAM;
  if (!strcmp(word,"cronjob")) return CFG_CRONJOB;
  if (!strcmp(word,"cscript")) return CFG_CSCRIPT;
  if (!strcmp(word,"data_buffer_length")) return CFG_DATABUFFER_LENGTH;
  if (!strcmp(word,"deny_access_files_uploaded")) return CFG_DENY_ACCESS_FUP;
  if (!strcmp(word,"dir_message")) return CFG_DIR_MESSAGE;
  if (!strcmp(word,"dynamic_ip")) return CFG_DYNAMIC_IP;
  if (!strcmp(word,"force_shm_cleanup")) return CFG_FORCE_SHM_CLEANUP;
  if (!strcmp(word,"hide_dotted_files")) return CFG_HIDE_DOTTED_FILES;
  if (!strcmp(word,"internal_sfv_checker")) return CFG_INTERNAL_SFV;
  if (!strcmp(word,"ip")) return CFG_IP;
  if (!strcmp(word,"logdir")) return CFG_LOGDIR;
  if (!strcmp(word,"logfile")) return CFG_LOGFILE;
  if (!strcmp(word,"loglevel")) return CFG_LOGLEVEL;
  if (!strcmp(word,"login_pre_ip_allowed")) return CFG_LOG_PRE_IP_ALLOW;
  if (!strcmp(word,"login_pre_ip_check")) return CFG_LOG_PRE_CHECK;
  if (!strcmp(word,"login_pre_ip_denied")) return CFG_LOG_PRE_IP_DENY;
  if (!strcmp(word,"max_dl_speed")) return CFG_MAX_DL_SPEED;
  if (!strcmp(word,"max_threads")) return CFG_MAX_THREADS;
  if (!strcmp(word,"max_ul_speed")) return CFG_MAX_UL_SPEED;
  if (!strncmp(word,"message_",strlen("message_"))) return CFG_MESSAGE;
  if (!strcmp(word,"module")) return CFG_MODULE;
  if (!strncmp(word,"param_",strlen("param_"))) return CFG_PARAM;
  if (!strcmp(word,"pasv_ip")) return CFG_PASV_IP;
  if (!strcmp(word,"pasv_low_range")) return CFG_PASV_LOW;
  if (!strcmp(word,"pasv_high_range")) return CFG_PASV_HIGH;
  if (!strcmp(word,"pid_file")) return CFG_PID_FILE;
  if (!strcmp(word,"port")) return CFG_PORT;
  if (!strcmp(word,"section")) return CFG_SECTION;
  if (!strcmp(word,"server_uid")) return CFG_SERVER_UID;
  if (!strcmp(word,"shm_key")) return CFG_SHM_KEY;
  if (!strcmp(word,"site_cmd")) return CFG_SITECMD;
  if (!strncmp(word,"sitefile_",strlen("sitefile_"))) return CFG_SITEFILE;
  if (!strncmp(word,"site_",strlen("site_"))) return CFG_SITE;
  if (!strcmp(word,"tls_certificate")) return CFG_TLS_CERT;
  if (!strcmp(word,"tls_cipher_list")) return CFG_TLS_CIPHER_LIST;
  if (!strcmp(word,"tls_mode")) return CFG_TLS_MODE;
  if (!strcmp(word,"umask")) return CFG_UMASK;
  if (!strcmp(word,"use_syslog")) return CFG_USE_SYSLOG;
  if (!strcmp(word,"vfs")) return CFG_VFS;
  if (!strcmp(word,"xferlog")) return CFG_XFERLOG;
  return 0;
}

int read_directive(void)
{
  unsigned int token;

  while ( (token=yylex()) )
  {
    if (token==CFG_EOL) return 0;
  }

  return 1;
}

int set_default_options(void)
{
/*  mainConfig = &tempConfig;*/
  setlib_mainConfig(mainConfig);
/*  setlib_mainConfig(&tempConfig);*/

  tempConfig.htab = wzd_malloc(sizeof(CHTBL));
  if (chtbl_init((CHTBL*)tempConfig.htab, 256, (hash_function)hash_str, (cmp_function)strcmp, free)) return -1;

  tempConfig.pid_file = wzd_strdup(WZD_DEFAULT_PIDFILE);

  tempConfig.config_filename=NULL;
  tempConfig.logdir=NULL;

  tempConfig.backend.handle=NULL;
  tempConfig.backend.param=NULL;

  tempConfig.site_closed=0;

  strcpy ((char*)tempConfig.ip, "*");
  strcpy ((char*)tempConfig.dynamic_ip, "0");
  tempConfig.port = 21;
  tempConfig.max_threads=32;

  tempConfig.umask = 0775;

  tempConfig.data_buffer_length = 16384; /* default data buffer is 16k */

  tempConfig.global_ul_limiter.maxspeed = 0;
  tempConfig.global_ul_limiter.bytes_transfered = 0;
  tempConfig.global_dl_limiter.maxspeed = 0;
  tempConfig.global_dl_limiter.bytes_transfered = 0;

  tempConfig.pasv_low_range = 1025;
  tempConfig.pasv_high_range = 65536;

  tempConfig.login_pre_ip_check = 0;
  tempConfig.login_pre_ip_allowed = NULL;
  tempConfig.login_pre_ip_denied = NULL;

  tempConfig.command_list = NULL;
  tempConfig.vfs = NULL;

  tempConfig.dir_message = NULL;

  tempConfig.server_opts = 0;

#if !defined(DEBUG)
#if !defined(_WIN32)
    CFG_SET_OPTION(&tempConfig,CFG_OPT_USE_SYSLOG);
#endif /* _WIN32 */
#else /* DEBUG */
    CFG_CLR_OPTION(&tempConfig,CFG_OPT_USE_SYSLOG);
#endif

/*  tempConfig.logfilename = wzd_malloc(256);
  strcpy(tempConfig.logfilename,"wzd.log");*/
  tempConfig.logfilename = NULL;

#if (defined (__FreeBSD__) && (__FreeBSD__ < 5)) || defined(_MSC_VER)
  tempConfig.logfilemode = O_CREAT | O_WRONLY | O_APPEND;
#else /* ! BSD */
  tempConfig.logfilemode = O_CREAT | O_WRONLY | O_APPEND | O_SYNC;
#endif /* BSD */

  tempConfig.logfile = NULL;

  tempConfig.xferlog_name = NULL;
  tempConfig.xferlog_fd = -1;

  tempConfig.controlfd = -1;

  tempConfig.loglevel=LEVEL_NORMAL;

  tempConfig.perm_list = NULL;
  tempConfig.site_list = NULL;
  tempConfig.section_list = NULL;
  tempConfig.param_list = NULL;

  /* site config */
  tempConfig.site_config.file_ginfo = NULL;
  tempConfig.site_config.file_group = NULL;
  tempConfig.site_config.file_groups = NULL;
  tempConfig.site_config.file_help = NULL;
  tempConfig.site_config.file_rules = NULL;
  tempConfig.site_config.file_swho = NULL;
  tempConfig.site_config.file_user = NULL;
  tempConfig.site_config.file_users = NULL;
  tempConfig.site_config.file_who = NULL;
  tempConfig.site_config.file_vfs = NULL;

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  memset(tempConfig.tls_certificate,0,sizeof(tempConfig.tls_certificate));
  strcpy(tempConfig.tls_cipher_list,"ALL");

  tempConfig.tls_type = TLS_EXPLICIT;
#else
  tempConfig.tls_type = TLS_NOTYPE;
#endif

  tempConfig.shm_key = 0x1331c0d3;

  memset(tempConfig.pasv_ip,0,16);

  return 0;
}

/* read_until_eol (max_length)
 *
 * returns the end of line, or NULL
 * the buffer is dynamically allocated, you MUST free it after use
*/
char * read_until_eol(unsigned int max_len)
{
  char *buffer;
  char c;
  char *end;
  unsigned int length;

  if (max_len <= 0 || max_len > 1048576) return NULL;
  /* read til EOL */
  buffer = wzd_malloc(max_len);
  length = 0;
  end=buffer;
  while ( (c = input()) && c!=(char)EOF && (c==' ' || c=='\t')) ; /* eat leading spaces */
  while ( c && c!=(char)EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= max_len) {
      out_err(LEVEL_HIGH,"line is too long (max %d chars)\n",max_len);
      wzd_free(buffer);
      return NULL;
    }
    c = input();
  }
  *end='\0';

  return buffer;
}

int do_permission_line(const char *permname, const char *permline)
{
  int ret;

  ret = perm_is_valid_perm(permname);
  if (ret) return 1;

  ret = perm_add_perm(permname, permline,&tempConfig);
  if (ret) return 1;

  return 0;
}

/* BACKEND (string)
 * name of a .so
 */
int cfg_read_backend(void)
{
/*  char name[HARD_BACKEND_NAME_LENGTH];*/
  char *line;
  char *name, *ptr;
  char * predicate = NULL, *version=NULL;
  unsigned int token;
  int i;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'backend = ...'\n");
    return 1;
  }

  if( !(line=read_until_eol(HARD_BACKEND_NAME_LENGTH)) ) {
    out_err(LEVEL_HIGH,"invalid argument\n");
    return 1;
  }

  /* TODO XXX FIXME we should not use this, it forbids names with spaces */
  ptr = line;
  if (ptr[0]=='"') {
    name = strtok_r(line,"\"",&ptr);
  } else {
    name = strtok_r(line," \t\r\n",&ptr);
  }
  if (!name) {
    out_err(LEVEL_HIGH,"missing backend name\n");
    wzd_free(line);
    return 1;
  }
  predicate = strtok_r(NULL," \t\r\n",&ptr);
  if (predicate)
    version = strtok_r(NULL," \t\r\n",&ptr);
  if (predicate && !version) {
    out_err(LEVEL_HIGH,"missing backend version\n");
    wzd_free(line);
    return 1;
  }

  i = backend_validate(name,predicate,version);
  if (!i) {
    if (tempConfig.backend.handle == NULL) {
      /*        i = backend_init(value);*/
      strncpy(tempConfig.backend.name,name,HARD_BACKEND_NAME_LENGTH-1);
    } else { /* multiple backends ?? */
      i=0;
    }
  }
  wzd_free(line);
  return i;
}

/* BACKEND_PARAM
*/
int cfg_read_backend_param(const char *backendname)
{
  unsigned int token;
  char * param;
  int ret;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'backend_param_<type> = ...'\n");
    return 1;
  }

  if( !(param=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid argument\n");
    return 1;
  }

  ret = 1;
  /* \todo XXX FIXME compare name to backend */
/*  if (strcasecmp("plaintext",backendname)==0)*/
  { tempConfig.backend.param = wzd_strdup(param); ret = 0; }

  wzd_free (param);
  return ret;
}

/* CRONJOB (unsigned int+string)
*/
int cfg_read_cronjob(void)
{
  char buffer[1024];
  char * command;
  char * line;
  char *end;
  unsigned int token;
  char *min,*hour,*day,*month,*day_of_week;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'cronjob = ...'\n");
    return 1;
  }

  if ( !(line=read_until_eol(1024)) ) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> <hour> <day> <month> <day_of_week> <command>'\n");
    return 1;
  }

  /* XXX FIXME is this buffer copy really usefull ?
   * remark: perhaps because strtok_r modifies the buffer ...
   */
  strncpy(buffer,line,1024);
  wzd_free(line);
  line = buffer;

  min = strtok_r(buffer," \t",&line);
  if (!min) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = -> <min> <- <hour> <day> <month> <day_of_week> <command>'\n");
    return 1;
  }

  hour = strtok_r(NULL," \t",&line);
  if (!hour) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> -> <hour> <- <day> <month> <day_of_week> <command>'\n");
    return 1;
  }

  day = strtok_r(NULL," \t",&line);
  if (!day) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> <hour> -> <day> <- <month> <day_of_week> <command>'\n");
    return 1;
  }

  month = strtok_r(NULL," \t",&line);
  if (!month) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> <hour> <day> -> <month> <- <day_of_week> <command>'\n");
    return 1;
  }

  day_of_week = strtok_r(NULL," \t",&line);
  if (!day_of_week) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> <hour> <day> <month> -> <day_of_week> <- <command>'\n");
    return 1;
  }

  command = strtok_r(NULL,"\n\r",&line);
  if (!command) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <min> <hour> <day> <month> <day_of_week> -> <command> <-'\n");
    return 1;
  }

  /* skip leading spaces */
  end = command;
  while (*end && (*end==' ' || *end=='\t')) end++;

/*  return cronjob_add(&crontab,NULL,end,l);*/
  return cronjob_add(&crontab,NULL,end,min,hour,day,month,day_of_week);
}

/* CSCRIPT (string)
*/
int cfg_read_cscript(void)
{
  char *command;
  char *eventname;
  unsigned int eventmask=0;
  char *end;
  unsigned int token;
  int ret;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'cscript = ...'\n");
    return 1;
  }
  if ( (token=yylex()) != CFG_ID ) {
    out_err(LEVEL_HIGH,"line should be 'cscript = <event> <command>'\n");
    return 1;
  }
  eventname = yytext;
  eventmask = str2event(eventname);
  if (!eventmask) {
    out_err(LEVEL_HIGH,"event name is invalid (%s)\n",eventname);
    return 1;
  }

  if( !(command=read_until_eol(1024)) ) {
    out_err(LEVEL_HIGH,"invalid command\n");
    return 1;
  }

  /* skip leading spaces */
  end = command;
  while (*end && (*end==' ' || *end=='\t')) end++;

  ret = hook_add_external(&tempConfig.hook,eventmask,end);
  wzd_free(command);

  return ret;
}


/* DATA BUFFER LENGTH (unsigned int)
*/
int cfg_read_data_buffer_length(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'data_buffer_length = num'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'data_buffer_length = num'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if (l) {
    tempConfig.data_buffer_length = l;
  }

  return 0;
}

/* DENY_ACCESS_FILES_UPLOADED (integer)
*/
int cfg_read_deny_access_fup(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'deny_access_files_uploaded = 0|1'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'deny_access_files_uploaded = 0|1'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if (l)
    CFG_SET_OPTION(&tempConfig,CFG_OPT_DENY_ACCESS_FILES_UPLOADED);
  else
    CFG_CLR_OPTION(&tempConfig,CFG_OPT_DENY_ACCESS_FILES_UPLOADED);

  return 0;
}

/* DIR_MESSAGE (string)
*/
int cfg_read_dir_message(void)
{
  char *filename;
  char *end;
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'dir_message = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid filename\n");
    return 1;
  }

  /* skip leading spaces */
  end = filename;
  while (*end && (*end==' ' || *end=='\t')) end++;

  tempConfig.dir_message = wzd_strdup(end);

  if (chtbl_insert((CHTBL*)tempConfig.htab, "dir_message", wzd_strdup(end), NULL, NULL, wzd_free))
    ; /* error */

  wzd_free(filename);

  return 0;
}

/* DYNAMIC_IP (ip)
*/
int cfg_read_dynamic_ip(void)
{
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'dynamic_ip = ...'\n");
    return 1;
  }

  switch( (token=yylex()) ) {
  case CFG_NUM:
/*    out_err(LEVEL_FLOOD,"dynamic_ip: NUM (%s)\n",yytext);*/
    if (strcmp(yytext,"0")==0 || strcmp(yytext,"1")==0) {
      strcpy((char *)tempConfig.dynamic_ip,yytext);
      return 0;
    }
    break;
  case CFG_IP_STR:
    out_err(LEVEL_INFO,"Dynamic ip: %s\n",yytext);
    {
      struct hostent *host;
      host = gethostbyname(yytext+1);
      if (!host) {
        out_err(LEVEL_HIGH,"Could NOT resolve ip %s (ip)\n",yytext);
        return 1;
      }
    }
    strncpy((char *)tempConfig.dynamic_ip,yytext+1,MAX_IP_LENGTH-1);
    break;
  default:
    out_err(LEVEL_INFO,"ip: read token %d (%c) yytext:\n",token,token,yytext);
    break;
  }

  return 0;
}

/* FORCE_SHM_CLEANUP (integer)
*/
int cfg_read_force_shm_cleanup(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'force_shm_cleanup = 0|1'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'force_shm_cleanup = 0|1'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if (l)
    CFG_SET_OPTION(&tempConfig,CFG_OPT_FORCE_SHM_CLEANUP);
  else
    CFG_CLR_OPTION(&tempConfig,CFG_OPT_FORCE_SHM_CLEANUP);

  return 0;
}

/* HIDE_DOTTED_FILES (integer)
*/
int cfg_read_hide_dotted_files(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'hide_dotted_files = 0|1'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'hide_dotted_files = 0|1'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if (l)
    CFG_SET_OPTION(&tempConfig,CFG_OPT_HIDE_DOTTED_FILES);
  else
    CFG_CLR_OPTION(&tempConfig,CFG_OPT_HIDE_DOTTED_FILES);

  return 0;
}

/* INTERNAL SFV CHECKER (integer)
*/
int cfg_read_internal_sfv(void)
{
  unsigned int token;
  unsigned long l;

  out_err(LEVEL_HIGH,"This option has been replaced by the SFV module (see docs).");
  return 1;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'internal_sfv_checker = 0|1'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'internal_sfv_checker = 0|1'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

#if INTERNAL_SFV
  if (l) {
    hook_add(&mainConfig->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
    hook_add(&mainConfig->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
    out_err(LEVEL_INFO,"Internal SFV registered\n");
  }
#else
  out_err(LEVEL_INFO,"Internal SFV checker disabled\n");
#endif

  return 0;
}

/* IP (ip)
*/
int cfg_read_ip(void)
{
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'ip = ...'\n");
    return 1;
  }

  switch( (token=yylex()) ) {
  case CFG_IP_NUM:
    strncpy((char *)tempConfig.ip,yytext,MAX_IP_LENGTH-1);
    break;
  case CFG_IP_STR:
    out_err(LEVEL_INFO,"Dynamic ip: %s\n",yytext);
    {
      struct hostent *host;
      host = gethostbyname(yytext+1);
      if (!host) {
        out_err(LEVEL_HIGH,"Could NOT resolve ip %s (ip)\n",yytext);
        return 1;
      }
    }
    strncpy((char *)tempConfig.ip,yytext+1,MAX_IP_LENGTH-1);
    break;
  case '*':
    tempConfig.ip[0]='*';
    tempConfig.ip[1]='\0';
    break;
  default:
    out_err(LEVEL_INFO,"ip: read token %d (%c) yytext:\n",token,token,yytext);
    break;
  }

  return 0;
}

/* LOGDIR
 * absolute dir name
 */
int cfg_read_logdir(void)
{
  unsigned int token;
  char * filename;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'logdir = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  tempConfig.logdir = filename; /* will be freed at server exit */

  return 0;
}

/* LOGFILE
 * absolute file name (default: wzd.log)
 */
int cfg_read_logfile(void)
{
  unsigned int token;
  char * filename;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'logfile = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  tempConfig.logfilename = filename; /* will be freed at server exit */
  if (chtbl_insert((CHTBL*)tempConfig.htab, "logfile", wzd_strdup(filename), NULL, NULL, wzd_free))
    ; /* error */

  return 0;
}

/* LOGIN_PRE_IP_ALLOWED (string)
*/
int cfg_read_login_pre_ip_allow(void)
{
  char ip[MAX_IP_LENGTH];
  char c;
  char *end;
  unsigned int token;
  unsigned int length;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'login_pre_ip_allowed = ...'\n");
    return 1;
  }

  /* read til EOL */
  length = 0;
  end=ip;
  while ( (c = input()) && c!=(char)EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= MAX_IP_LENGTH) {
      out_err(LEVEL_HIGH,"ip is too long (max %d chars)\n",MAX_IP_LENGTH);
      return 1;
    }
  }
  *end='\0';

  /* skip leading spaces */
  end = ip;
  while (*end && (*end==' ' || *end=='\t')) end++;

  if (ip_add(&tempConfig.login_pre_ip_allowed,end)) return 1;
  return 0;
}


/* LOGIN_PRE_IP_CHECK (integer)
*/
int cfg_read_login_pre_ip_check(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'login_pre_ip_check = 0|1|2'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'login_pre_ip_check = 0|1|2'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if ((*yytext != '0' && *yytext != '1' && *yytext != '2')
      || *(yytext+1)!='\0')
    return 1;
  tempConfig.login_pre_ip_check = (*yytext) - '0';

  return 0;
}

/* LOGIN_PRE_IP_DENIED (string)
*/
int cfg_read_login_pre_ip_deny(void)
{
  char ip[MAX_IP_LENGTH];
  char c;
  char *end;
  unsigned int token;
  unsigned int length;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'login_pre_ip_denied = ...'\n");
    return 1;
  }

  /* read til EOL */
  length = 0;
  end=ip;
  while ( (c = input()) && c!=(char)EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= MAX_IP_LENGTH) {
      out_err(LEVEL_HIGH,"ip is too long (max %d chars)\n",MAX_IP_LENGTH);
      return 1;
    }
  }
  *end='\0';

  /* skip leading spaces */
  end = ip;
  while (*end && (*end==' ' || *end=='\t')) end++;

  if (ip_add(&tempConfig.login_pre_ip_denied,end)) return 1;
  return 0;
}

/* LOGLEVEL (string)
*/
int cfg_read_loglevel(void)
{
  unsigned int token;
  int i;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'loglevel = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_ID ) {
    out_err(LEVEL_HIGH,"valid levels are lowest, flood, info, normal, high, critical\n");
    return 1;
  }

  i = str2loglevel(yytext);
  if( i==-1 ) {
    out_err(LEVEL_HIGH,"valid levels are lowest, flood, info, normal, high, critical\n");
    return 1;
  }

  if (chtbl_insert((CHTBL*)tempConfig.htab, "loglevel", wzd_strdup(yytext), NULL, NULL, wzd_free))
    ; /* error */

  tempConfig.loglevel = i;

  return 0;
}




/* MAX_DL_SPEED (unsigned long)
*/
int cfg_read_max_dl_speed(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'max_dl_speed = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"max_dl_speed must be a positive or nul number\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  tempConfig.global_dl_limiter.maxspeed = l;

  return 0;
}


/* MAX_THREADS (int)
 * must be between 1 and 2000
 */
int cfg_read_maxthreads(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'max_threads = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"max_threads must be a number within 1 and 2000 inclusive'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;
  if (l < 1 || l > 2000) {
    out_err(LEVEL_HIGH,"max_threads must be between 1 and 2000 inclusive\n");
    return 1;
  }
  tempConfig.max_threads = (int)l;

  return 0;
}

/* MAX_UL_SPEED (unsigned long)
*/
int cfg_read_max_ul_speed(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'max_ul_speed = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"max_ul_speed must be a positive or nul number\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  tempConfig.global_ul_limiter.maxspeed = l;

  return 0;
}

/* MESSAGE (string)
*/
int cfg_read_message(unsigned long l)
{
  char *message;
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'message_<num> = ...'\n");
    return 1;
  }

  if( !(message=read_until_eol(HARD_MSG_LENGTH_MAX)) ) {
    out_err(LEVEL_HIGH,"invalid command\n");
    return 1;
  }

  /* memory will be free at server exit */
  setMessage(message,(int)l);
  
  return 0;
}

/* MODULE (string)
*/
int cfg_read_module(void)
{
  unsigned int token;
  char * name;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'module = ...'\n");
    return 1;
  }

  if( !(name=read_until_eol(512)) ) {
    out_err(LEVEL_HIGH,"invalid module name\n");
    return 1;
  }

  if (module_check(name)) { wzd_free(name); return 1; }
  /* add module to list */
  if (module_add(&tempConfig.module,name)) { wzd_free(name); return 1; }

  wzd_free(name);
  return 0;
}


/* PARAM
*/
int cfg_read_param(const char *paramname)
{
  unsigned int token;
  char * data;
  int ret;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'param_<name> = ...'\n");
    return 1;
  }

  if( !(data=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid argument\n");
    return 1;
  }

  ret = server_set_param(paramname,data,strlen(data),&tempConfig.param_list);

  wzd_free (data);
  return ret;
}


/* PASV_IP (ip)
*/
int cfg_read_pasv_ip(void)
{
  unsigned int token;
  unsigned int new_ip[4];
  int r;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'pasv_ip = ...'\n");
    return 1;
  }

  switch( (token=yylex()) ) {
  case CFG_IP_NUM:
    r = sscanf(yytext,"%u.%u.%u.%u",&new_ip[0],&new_ip[1],&new_ip[2],&new_ip[3]);
    if (r!=4 || new_ip[0] >= 255 || new_ip[1] >= 255 || new_ip[2] >= 255 || new_ip[3] >= 255)
      return 1;
    break;
  case CFG_IP_STR:
    {
      struct hostent *host;
      unsigned char *host_ip;
      host = gethostbyname(yytext+1);
      if (!host) {
        out_err(LEVEL_HIGH,"Could NOT resolve ip %s (pasv_ip)\n",yytext);
        return 1;
      }
      host_ip = (unsigned char*)(host->h_addr);
      new_ip[0] = host_ip[0];
      new_ip[1] = host_ip[1];
      new_ip[2] = host_ip[2];
      new_ip[3] = host_ip[3];
    }
    break;
  default:
    out_err(LEVEL_INFO,"ip: read token %d (%c) yytext:\n",token,token,yytext);
    return 1;
  }

  tempConfig.pasv_ip[0] = (unsigned char)new_ip[0];
  tempConfig.pasv_ip[1] = (unsigned char)new_ip[1];
  tempConfig.pasv_ip[2] = (unsigned char)new_ip[2];
  tempConfig.pasv_ip[3] = (unsigned char)new_ip[3];

  return 0;
}


/* PASV_LOW_RANGE (unsigned long)
*/
int cfg_read_pasv_low(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'pasv_low_range = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"pasv_low_range must be a positive or nul number\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  tempConfig.pasv_low_range = l;

  return 0;
}

/* PASV_HIGH_RANGE (unsigned long)
*/
int cfg_read_pasv_high(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'pasv_high_range = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"pasv_high_range must be a positive or nul number\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  tempConfig.pasv_high_range = l;

  return 0;
}

/* PID_FILE
 * absolute file name
 */
int cfg_read_pid_file(void)
{
  unsigned int token;
  char * filename;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'pid_file = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  if (tempConfig.pid_file) wzd_free(tempConfig.pid_file);
  tempConfig.pid_file = filename; /* will be freed at server exit */

  return 0;
}

/* PORT (int)
 * 2 remarks:
 * - use strtoul (instead of atoi) to detect errors
 * - base can be 10 (default), 16 ( 0xnum ) or 8 ( 0num )
 */
int cfg_read_port(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'port = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"port must be a number within 1 and 65535'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;
  if (l < 1 || l > 65535) {
    out_err(LEVEL_HIGH,"port must be between 1 and 65535 inclusive\n");
    return 1;
  }
  tempConfig.port = l;

  return 0;
}

/* SECTION (string)
*/
int cfg_read_section(void)
{
  char *sectionmask;
  char *sectionname;
  char *filter, *ptr;
  char buffer[256];
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'section = ...'\n");
    return 1;
  }

  if( !(ptr=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"line should be 'section = <name> <mask> <regexp>'\n");
    return 1;
  }

  strncpy(buffer,ptr,256);
  wzd_free(ptr);

  sectionname = strtok_r(buffer," \t\n\r",&ptr);
  if( !sectionname ) {
    out_err(LEVEL_HIGH,"invalid name\n");
    return 1;
  }
  sectionmask = strtok_r(NULL," \t\n\r",&ptr);
  if( !sectionmask ) {
    out_err(LEVEL_HIGH,"invalid mask\n");
    return 1;
  }

  filter = strtok_r(NULL,"\n\r",&ptr);

  if (section_add(&tempConfig.section_list,sectionname,sectionmask,filter))
  {
    return 1;
  }
  return 0;
}

/* SERVER_UID (unsigned int/string)
*/
int cfg_read_server_uid(void)
{
  unsigned int token;
  unsigned long l;
  char *ptr;
  int wzd_server_uid;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'server_uid = ...'\n");
    return 1;
  }

  switch( (token=yylex()) ) {
  case CFG_NUM:
    errno = 0;
    l = strtoul(yytext,(char**)&ptr, 0);
    wzd_server_uid = (unsigned int)l;
    setlib_server_uid(wzd_server_uid);
    return 0;
#ifndef WIN32
  case CFG_ID:
    { /* not a number, try a login */
      struct passwd * p;
      p = getpwnam(yytext);
      if (!p) {
        out_err(LEVEL_HIGH,"server_uid: could not find uid for user %s\n",yytext);
        return 1;
      }
      wzd_server_uid = p->pw_uid;
      setlib_server_uid(wzd_server_uid);
      return 0;
    }
#endif
  default:
    out_err(LEVEL_INFO,"server_uid: read token %d (%c) yytext:\n",token,token,yytext);
    return 1;
  }

  return 1;
}

/* SHM_KEY (unsigned long)
*/
int cfg_read_shm_key(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'shm_key = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"shm_key must be a positive or nul number\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

#ifdef DEBUG
  out_err(LEVEL_INFO,"******* changing shm_key: new value 0x%lx\n",l);
#endif
  tempConfig.shm_key = l;

  return 0;
}

/* SITE CONFIG
*/
int cfg_read_sitefile(const char *type)
{
  unsigned int token;
  char * filename;
  int ret;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'sitefile_<type> = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  ret = 1;
  if (strcasecmp("ginfo",type)==0)
  { tempConfig.site_config.file_ginfo = filename; ret = 0; }
  if (strcasecmp("groups",type)==0)
  { tempConfig.site_config.file_groups = filename; ret = 0; }
  if (strcasecmp("group",type)==0)
  { tempConfig.site_config.file_group = filename; ret = 0; }
  if (strcasecmp("help",type)==0)
  { tempConfig.site_config.file_help = filename; ret = 0; }
  if (strcasecmp("rules",type)==0)
  { tempConfig.site_config.file_rules = filename; ret = 0; }
  if (strcasecmp("swho",type)==0)
  { tempConfig.site_config.file_swho = filename; ret = 0; }
  if (strcasecmp("user",type)==0)
  { tempConfig.site_config.file_user = filename; ret = 0; }
  if (strcasecmp("users",type)==0)
  { tempConfig.site_config.file_users = filename; ret = 0; }
  if (strcasecmp("who",type)==0)
  { tempConfig.site_config.file_who = filename; ret = 0; }
  if (strcasecmp("vfs",type)==0)
  { tempConfig.site_config.file_vfs = filename; ret = 0; }

  /* if ret is 0, filename will be freed at server exit */
  if (ret==1)
    wzd_free (filename);

  return ret;
}

/* SITE_CMD (string)
*/
int cfg_read_sitecmd(void)
{
  char *command;
  char *sitecmdname;
  unsigned int token;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'site_cmd = ...'\n");
    return 1;
  }
  if ( (token=yylex()) != CFG_ID ) {
    out_err(LEVEL_HIGH,"line should be 'site_cmd = <name> <command>'\n");
    return 1;
  }
  sitecmdname = wzd_strdup(yytext);
  /* TODO check command unicity ? */

  if( !(command=read_until_eol(1024)) ) {
    out_err(LEVEL_HIGH,"invalid command\n");
    return 1;
  }

  if (hook_add_custom_command(&tempConfig.hook,sitecmdname,command))
  {
    wzd_free(sitecmdname);
    wzd_free(command);
    return 1;
  }
  wzd_free(sitecmdname);
  wzd_free(command);
  return 0;
}


/* TLS CERTIFICATE
 * absolute file name
 */
int cfg_read_tls_certificate(void)
{
  unsigned int token;
  char * filename;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'tls_certificate = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  strcpy(tempConfig.tls_certificate,filename);
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* HAVE_OPENSSL */

  wzd_free(filename);
  return 0;
}

/* TLS CIPHER LIST
 * string
 */
int cfg_read_tls_cipher_list(void)
{
  unsigned int token;
  char * buffer;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'tls_cipher_list = ...'\n");
    return 1;
  }

  if( !(buffer=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid cipher list\n");
    return 1;
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  strcpy(tempConfig.tls_cipher_list,buffer);
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* HAVE_OPENSSL */

  wzd_free(buffer);
  return 0;
}

/* TLS MODE
 * string: implicit/explicit/explicit_strict
 */
int cfg_read_tls_mode(void)
{
  unsigned int token;
  char * buffer;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'tls_mode = ...'\n");
    return 1;
  }

  if( !(buffer=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid mode\n");
    return 1;
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    if (strcasecmp("explicit",buffer)==0)
      tempConfig.tls_type = TLS_EXPLICIT;
    else if (strcasecmp("explicit_strict",buffer)==0)
      tempConfig.tls_type = TLS_STRICT_EXPLICIT;
    else if (strcasecmp("implicit",buffer)==0)
      tempConfig.tls_type = TLS_IMPLICIT;
    else
    {
      out_err(LEVEL_HIGH,"invalid mode\n");
      wzd_free(buffer);
      return 1;
    }
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* HAVE_OPENSSL */

  wzd_free(buffer);
  return 0;
}


/* UMASK (integer)
*/
int cfg_read_umask(void)
{
  unsigned int token;
  unsigned long l;
  char *ptr;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'umask = <octal number>'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'umask = <octal number>'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,&ptr, 8);
  if (errno==ERANGE)
    return 1;

  if (*ptr == '\0')
    tempConfig.umask = (unsigned int)l;
  else
    out_err(LEVEL_HIGH,"line should be 'umask = <octal number>'\n");

  return 0;
}


/* USE_SYSLOG (integer)
*/
int cfg_read_use_syslog(void)
{
  unsigned int token;
  unsigned long l;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'use_syslog = 0|1'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'use_syslog = 0|1'\n");
    return 1;
  }

  errno = 0;
  l = strtoul(yytext,(char**)NULL, 0);
  if (errno==ERANGE)
    return 1;

  if (l)
    CFG_SET_OPTION(&tempConfig,CFG_OPT_USE_SYSLOG);
  else
    CFG_CLR_OPTION(&tempConfig,CFG_OPT_USE_SYSLOG);

  return 0;
}


/* VFS : Virtual FileSystem
 */
int cfg_read_vfs(void)
{
  unsigned int token;
  char * buffer;
  char virtual_path[1024];
  char physical_path[1024];
  char delimiter;
  const char *ptr;
  char *dstptr;
  unsigned int dstlen;
  const char *target;
  int ret;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'vfs = ...'\n");
    return 1;
  }

  if( !(buffer=read_until_eol(2048)) ) {
    out_err(LEVEL_HIGH,"invalid vfs\n");
    return 1;
  }

  ptr = buffer;

  if (strlen(ptr) < 5) return 1; /* basic precaution */
  delimiter = *ptr++;

  dstptr = virtual_path;
  dstlen = 0;
  while (*ptr) {
    if (*ptr == delimiter) break; /* end */
    if (dstlen++ == 1023) break; /* too long */
    *dstptr++ = *ptr++;
  }
  if (!*ptr || *ptr != delimiter) return 1;
  *dstptr = '\0';

  dstptr = physical_path;
  dstlen = 0;
  ptr++;
  while (*ptr) {
    if (*ptr == delimiter) break; /* end */
    if (dstlen++ == 1023) break; /* too long */
    *dstptr++ = *ptr++;
  }
  if (!*ptr || *ptr != delimiter) return 1;
  *dstptr = '\0';

  /* TODO chek if condition present */
  target=NULL;
  ptr++;
  if (*ptr) {
    while( *ptr && (*ptr==' ' || *ptr=='\t')) ptr++;
    if (*ptr)
      target=ptr;
  }

  if (target)
    ret = vfs_add_restricted(&tempConfig.vfs,virtual_path,physical_path,target);
  else
    ret = vfs_add(&tempConfig.vfs,virtual_path,physical_path);
  if (ret) {
    wzd_free(buffer);
    out_err(LEVEL_HIGH,"There was a problem adding vfs %s => %s\n",virtual_path,physical_path);
    out_err(LEVEL_HIGH,"Please check destination exists and you have correct permissions\n");
    return 1;
  }

  wzd_free(buffer);
  return 0;
}

/* XFERLOG
 * absolute file name
 */
int cfg_read_xferlog(void)
{
  unsigned int token;
  char * filename;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'xferlog = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  tempConfig.xferlog_name = filename; /* will be freed at server exit */

  return 0;
}







wzd_config_t * readConfigFile(const char *fileName)
{
/*  char current_token[256];*/
  unsigned int token;
  int ret;

  if (!fileName || strlen(fileName)==0) return NULL;

#ifdef WIN32
  yy_init=1;
#endif

  yyin = fopen(fileName,"r");
  if (!yyin) {
/*    fprintf(stderr,"Unable to open file\n");*/
    return NULL;
  }

  init_default_messages();
  set_default_options();

  while ( (token=yylex()) )
  {
    switch (token) {
    case CFG_EOL:
      break;
    case CFG_BACKEND:
      ret = cfg_read_backend();
      break;
    case CFG_BACKEND_PARAM:
      {
        char *buf;
        if (strlen(yytext)<=strlen("backend_param_") || strlen(yytext)>=256) {
          out_err(LEVEL_HIGH,"token too long\n");
          continue;
        }
        buf = wzd_strdup(yytext+strlen("backend_param_"));
        ret = cfg_read_backend_param(buf);
        wzd_free(buf);
      }
      break;
    case CFG_CRONJOB:
      ret = cfg_read_cronjob();
      break;
    case CFG_CSCRIPT:
      ret = cfg_read_cscript();
      break;
    case CFG_DATABUFFER_LENGTH:
      ret = cfg_read_data_buffer_length();
      break;
    case CFG_DENY_ACCESS_FUP:
      ret = cfg_read_deny_access_fup();
      break;
    case CFG_DIR_MESSAGE:
      ret = cfg_read_dir_message();
      break;
    case CFG_DYNAMIC_IP:
      ret = cfg_read_dynamic_ip();
      break;
    case CFG_FORCE_SHM_CLEANUP:
      ret = cfg_read_force_shm_cleanup();
      break;
    case CFG_HIDE_DOTTED_FILES:
      ret = cfg_read_hide_dotted_files();
      break;
    case CFG_INTERNAL_SFV:
      ret = cfg_read_internal_sfv();
      break;
    case CFG_IP:
      ret = cfg_read_ip();
      break;
    case CFG_LOGDIR:
      ret = cfg_read_logdir();
      break;
    case CFG_LOGFILE:
      ret = cfg_read_logfile();
      break;
    case CFG_LOG_PRE_IP_ALLOW:
      ret = cfg_read_login_pre_ip_allow();
      break;
    case CFG_LOG_PRE_CHECK:
      ret = cfg_read_login_pre_ip_check();
      break;
    case CFG_LOG_PRE_IP_DENY:
      ret = cfg_read_login_pre_ip_deny();
      break;
    case CFG_LOGLEVEL:
      ret = cfg_read_loglevel();
      break;
    case CFG_MAX_DL_SPEED:
      ret = cfg_read_max_dl_speed();
      break;
    case CFG_MAX_THREADS:
      ret = cfg_read_maxthreads();
      break;
    case CFG_MAX_UL_SPEED:
      ret = cfg_read_max_ul_speed();
      break;
    case CFG_MESSAGE:
      {
        unsigned long l;
        errno = 0;
        if (strlen(yytext)<=strlen("message_") || strlen(yytext)>=15) {
          out_err(LEVEL_HIGH,"token too long\n");
          continue;
        }
        l = strtoul(yytext+strlen("message_"),(char**)NULL, 0);
        if (errno==ERANGE || l > HARD_MSG_LIMIT) {
          out_err(LEVEL_HIGH,"Invalid message number\n");
          continue;
        }
        ret = cfg_read_message(l);
      }
      break;
    case CFG_MODULE:
      ret = cfg_read_module();
      break;
    case CFG_PARAM:
      {
        char *buf;
        if (strlen(yytext)<=strlen("param_") || strlen(yytext)>=256) {
          out_err(LEVEL_HIGH,"token too long\n");
          continue;
        }
        buf = wzd_strdup(yytext+strlen("param_"));
        ret = cfg_read_param(buf);
        wzd_free(buf);
      }
      break;

    case CFG_PASV_IP:
      ret = cfg_read_pasv_ip();
      break;
    case CFG_PASV_LOW:
      ret = cfg_read_pasv_low();
      break;
    case CFG_PASV_HIGH:
      ret = cfg_read_pasv_high();
      break;
    case CFG_PID_FILE:
      ret = cfg_read_pid_file();
      break;
    case CFG_PORT:
      ret = cfg_read_port();
      break;
    case CFG_SECTION:
      ret = cfg_read_section();
      break;
    case CFG_SERVER_UID:
      ret = cfg_read_server_uid();
      break;
    case CFG_SHM_KEY:
      ret = cfg_read_shm_key();
      break;
    case CFG_SITECMD:
      ret = cfg_read_sitecmd();
      break;
    case CFG_SITEFILE:
      {
        char *buf;
        if (strlen(yytext)<=strlen("sitefile_") || strlen(yytext)>=256) {
          out_err(LEVEL_HIGH,"token too long\n");
          continue;
        }
        buf = wzd_strdup(yytext+strlen("sitefile_"));
        ret = cfg_read_sitefile(buf);
        wzd_free(buf);
      }
      break;
    case CFG_TLS_CERT:
      ret = cfg_read_tls_certificate();
      break;
    case CFG_TLS_CIPHER_LIST:
      ret = cfg_read_tls_cipher_list();
      break;
    case CFG_TLS_MODE:
      ret = cfg_read_tls_mode();
      break;
    case CFG_UMASK:
      ret = cfg_read_umask();
      break;
    case CFG_USE_SYSLOG:
      ret = cfg_read_use_syslog();
      break;
    case CFG_VFS:
      ret = cfg_read_vfs();
      break;
    case CFG_XFERLOG:
      ret = cfg_read_xferlog();
      break;
#if 0
/*      printf("ID: %s\n",yytext);*/
      if (strlen(yytext)>=256) {
        printf("token too long: '%s'\n",yytext);
        continue;
      }
      strncpy(current_token,yytext,255);
      if (read_directive()) {
        printf("error reading directive %s\n",current_token);
        continue;
      }
      break;
#endif /* 0 */
    case '-': /* permission */
      {
        char permission_name[256];
        char * permission_line;
        token = yylex();
        /* XXX the following is now disabled because we allow to set permissions on
         * some commands, not just only site commands
         */
/*        if (token != CFG_SITE) {
          out_err(LEVEL_HIGH,"Invalid config line near token %s (%u)\n",yytext,token);
          continue;
        }*/
/*        printf("PERM: %s\n",yytext);*/
        if (strlen(yytext)>=256) {
          printf("token too long: '%s'\n",yytext);
          continue;
        }
        strncpy(permission_name,yytext,255);
        if ((token=yylex())!='=') {
          out_err(LEVEL_HIGH,"invalid permission line\n");
          continue;
        }
        if ( !(permission_line=read_until_eol(256)) ) {
          out_err(LEVEL_HIGH,"Line too long\n");
          continue;
        }
        ascii_lower(permission_name,strlen(permission_name));
        ret = do_permission_line(permission_name,permission_line);
        wzd_free(permission_line);
      }
      break;
    default:
      {
        char *ptr;
        ptr = read_until_eol(255);
        printf("Invalid config line near token %u\n %s %s\n",token,yytext,ptr);
        /* eat line */
        wzd_free(ptr);
        continue;
      }
    }
  }

  fclose(yyin);
  return &tempConfig;
}

int yywrap(void)
{ return 1; }
