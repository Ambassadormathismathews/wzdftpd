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
%x str

%{

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>	/* gethostbyname() */
#include <limits.h>	/* ULONG_MAX */

#ifndef __CYGWIN__
#include <pwd.h>	/* getpwnam() */
#endif

/* speed up compilation */
#define	SSL	void
#define	SSL_CTX	void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_libmain.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_perm.h"
#include "wzd_crontab.h"
#include "wzd_ServerThread.h"
#include "wzd_vfs.h"

#define	CFG_ID			256
#define	CFG_IP_NUM		257
#define	CFG_IP_STR		258
#define	CFG_NUM			259
#define	CFG_EOL			264
#define	CFG_EQUAL		265
#define	CFG_LOWER_EQ		266
#define	CFG_GREATER_EQ		267

#define	CFG_BACKEND		300
#define	CFG_BACKEND_PARAM	301
#define	CFG_CRONJOB		302
#define	CFG_CSCRIPT		303
#define	CFG_DENY_ACCESS_FUP	304
#define	CFG_DIR_MESSAGE		305
#define	CFG_DYNAMIC_IP		306
#define	CFG_INTERNAL_SFV	307
#define	CFG_IP			308
#define	CFG_LOGLEVEL		309
#define	CFG_LOG_PRE_CHECK	310
#define	CFG_LOG_PRE_IP_ALLOW	311
#define	CFG_LOG_PRE_IP_DENY	312
#define	CFG_MAX_DL_SPEED	313
#define	CFG_MAX_THREADS		314
#define	CFG_MAX_UL_SPEED	315
#define	CFG_MESSAGE		316
#define	CFG_MODULE		317
#define	CFG_PASV_IP		318
#define	CFG_PASV_LOW		319
#define	CFG_PASV_HIGH		320
#define	CFG_PORT		321
#define	CFG_SERVER_UID		322
#define	CFG_SHM_KEY		323
#define	CFG_SITE		324
#define	CFG_SITECMD		325
#define	CFG_SITEFILE		326
#define	CFG_TLS_CERT		327
#define	CFG_TLS_CIPHER_LIST	328
#define	CFG_TLS_MODE		329
#define	CFG_VFS			330
#define	CFG_XFERLOG		331

#define	CFG_UNKNOWN	511

unsigned int cfg_is_keyword(const char *word);

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

unsigned int cfg_is_keyword(const char *word)
{
  /* order IS important for some keywords (site) */
  if (!strcasecmp(word,"backend")) return CFG_BACKEND;
  if (!strncasecmp(word,"backend_param_",strlen("backend_param_")))
    return CFG_BACKEND_PARAM;
  if (!strcasecmp(word,"cronjob")) return CFG_CRONJOB;
  if (!strcasecmp(word,"cscript")) return CFG_CSCRIPT;
  if (!strcasecmp(word,"deny_access_files_uploaded")) return CFG_DENY_ACCESS_FUP;
  if (!strcasecmp(word,"dir_message")) return CFG_DIR_MESSAGE;
  if (!strcasecmp(word,"dynamic_ip")) return CFG_DYNAMIC_IP;
  if (!strcasecmp(word,"internal_sfv_checker")) return CFG_INTERNAL_SFV;
  if (!strcasecmp(word,"ip")) return CFG_IP;
  if (!strcasecmp(word,"loglevel")) return CFG_LOGLEVEL;
  if (!strcasecmp(word,"login_pre_ip_allowed")) return CFG_LOG_PRE_IP_ALLOW;
  if (!strcasecmp(word,"login_pre_ip_check")) return CFG_LOG_PRE_CHECK;
  if (!strcasecmp(word,"login_pre_ip_denied")) return CFG_LOG_PRE_IP_DENY;
  if (!strcasecmp(word,"max_dl_speed")) return CFG_MAX_DL_SPEED;
  if (!strcasecmp(word,"max_threads")) return CFG_MAX_THREADS;
  if (!strcasecmp(word,"max_ul_speed")) return CFG_MAX_UL_SPEED;
  if (!strncasecmp(word,"message_",strlen("message_"))) return CFG_MESSAGE;
  if (!strcasecmp(word,"module")) return CFG_MODULE;
  if (!strcasecmp(word,"pasv_ip")) return CFG_PASV_IP;
  if (!strcasecmp(word,"pasv_low_range")) return CFG_PASV_LOW;
  if (!strcasecmp(word,"pasv_high_range")) return CFG_PASV_HIGH;
  if (!strcasecmp(word,"port")) return CFG_PORT;
  if (!strcasecmp(word,"server_uid")) return CFG_SERVER_UID;
  if (!strcasecmp(word,"shm_key")) return CFG_SHM_KEY;
  if (!strcasecmp(word,"site_cmd")) return CFG_SITECMD;
  if (!strncasecmp(word,"sitefile_",strlen("sitefile_"))) return CFG_SITEFILE;
  if (!strncasecmp(word,"site_",strlen("site_"))) return CFG_SITE;
  if (!strcasecmp(word,"tls_certificate")) return CFG_TLS_CERT;
  if (!strcasecmp(word,"tls_cipher_list")) return CFG_TLS_CIPHER_LIST;
  if (!strcasecmp(word,"tls_mode")) return CFG_TLS_MODE;
  if (!strcasecmp(word,"vfs")) return CFG_VFS;
  if (!strcasecmp(word,"xferlog")) return CFG_XFERLOG;
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

  tempConfig.config_filename=NULL;

  tempConfig.backend.handle=NULL;
  tempConfig.backend.param=NULL;

  tempConfig.site_closed=0;

  tempConfig.ip[0] = '\0';
  tempConfig.dynamic_ip[0] = '\0';
  tempConfig.port = 21;
  tempConfig.max_threads=32;

  tempConfig.global_ul_limiter.maxspeed = 0;
  tempConfig.global_ul_limiter.bytes_transfered = 0;
  tempConfig.global_dl_limiter.maxspeed = 0;
  tempConfig.global_dl_limiter.bytes_transfered = 0;

  tempConfig.pasv_low_range = 1025;
  tempConfig.pasv_high_range = 65536;

  tempConfig.login_pre_ip_check = 0;
  tempConfig.login_pre_ip_allowed = NULL;
  tempConfig.login_pre_ip_denied = NULL;

  tempConfig.vfs = NULL;

  tempConfig.dir_message[0] = 0;

  tempConfig.logfilename = malloc(256);
  strcpy(tempConfig.logfilename,"wzd.log");

  tempConfig.logfilemode = O_CREAT | O_WRONLY | O_APPEND | O_SYNC;

  tempConfig.logfile = NULL;

  tempConfig.xferlog_name = NULL;
  tempConfig.xferlog_fd = -1;

  tempConfig.loglevel=LEVEL_NORMAL;

  tempConfig.perm_list = NULL;
  tempConfig.site_list = NULL;

  /* site config */
  tempConfig.site_config.file_help[0] = '\0';
  tempConfig.site_config.file_rules[0] = '\0';
  tempConfig.site_config.file_swho[0] = '\0';
  tempConfig.site_config.file_user[0] = '\0';
  tempConfig.site_config.file_users[0] = '\0';
  tempConfig.site_config.file_who[0] = '\0';

#ifdef SSL_SUPPORT
  memset(tempConfig.tls_certificate,0,sizeof(tempConfig.tls_certificate));
  strcpy(tempConfig.tls_cipher_list,"ALL");

  tempConfig.tls_type = TLS_NOTYPE;
#endif

  tempConfig.shm_key = 0x1331c0d3;

  memset(tempConfig.pasv_ip,0,4);

  tempConfig.server_opts = 0;

  return 0;
}

/* read_until_eol (max_length)
 *
 * returns the end of line, or NULL
 * the buffer is dynamically allocated, you MUST free it after use
*/
char * read_until_eol(int max_len)
{
  char *buffer;
  char c;
  char *end;
  unsigned int length;

  if (max_len <= 0 || max_len > 1048576) return NULL;
  /* read til EOL */
  buffer = malloc(max_len);
  length = 0;
  end=buffer;
  while ( (c = input()) && c!=EOF && (c==' ' || c=='\t')) ; /* eat leading spaces */
  while ( c && c!=EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= max_len) {
      out_err(LEVEL_HIGH,"line is too long (max %d chars)\n",max_len);
      free(buffer);
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
  char name[HARD_BACKEND_NAME_LENGTH];
  char * predicate = NULL, *version=NULL;
  unsigned int token;
  int i;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'backend = ...'\n");
    return 1;
  }
  if ( (token=yylex()) != CFG_ID ) {
    out_err(LEVEL_HIGH,"line should be 'backend = name [> version]'\n");
    return 1;
  }
  if (strlen(yytext)>=HARD_BACKEND_NAME_LENGTH) {
    out_err(LEVEL_HIGH,"backend name is too long (>= %d chars)\n",HARD_BACKEND_NAME_LENGTH);
    return 1;
  }
  strcpy(name,yytext);

  token = yylex();
  if (token=='>') {
    predicate=strdup(">");
    if ( (token = yylex()) != CFG_NUM || strlen(yytext)>=10) {
      out_err(LEVEL_HIGH,"backend version should be an integer (e.g 122)\n");
      return 1;
    }
    version=strdup(yytext);
  }
#ifdef DEBUG
  out_err(LEVEL_INFO,"trying backend; '%s'\n",name);
#endif
  i = backend_validate(name,predicate,version);
  if (!i) {
    if (tempConfig.backend.handle == NULL) {
      /*        i = backend_init(value);*/
      strncpy(tempConfig.backend.name,name,HARD_BACKEND_NAME_LENGTH-1);
    } else { /* multiple backends ?? */
      i=0;
    }
  }
  if (predicate) free(predicate);
  if (version) free(version);
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
  if (strcasecmp("plaintext",backendname)==0)
  { tempConfig.backend.param =strdup(param); ret = 0; }

  free (param);
  return ret;
}

/* CRONJOB (unsigned int+string)
*/
int cfg_read_cronjob(void)
{
  char command[1024];
  char c;
  char *end;
  unsigned int token;
  unsigned long l;
  unsigned int length;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'cronjob = ...'\n");
    return 1;
  }
  if ( (token=yylex()) != CFG_NUM ) {
    out_err(LEVEL_HIGH,"line should be 'cronjob = <interval> <command>'\n");
    return 1;
  }
  l = strtoul(yytext,&end,0);
  if (end == yytext) { return 1; }
  if (l==ULONG_MAX && errno==ERANGE) { return 1; }

  length = 0;
  end=command;
  while ( (c = input()) && c!=EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= 1024) {
      out_err(LEVEL_HIGH,"command is too long (max 1024 chars)\n");
      return 1;
    }
  }
  *end='\0';

  /* skip leading spaces */
  end = command;
  while (*end && (*end==' ' || *end=='\t')) end++;

  return cronjob_add(&crontab,NULL,end,l);
}

/* CSCRIPT (string)
*/
int cfg_read_cscript(void)
{
  char command[1024];
  char *eventname;
  unsigned int eventmask=0;
  char c;
  char *end;
  unsigned int token;
  unsigned int length;

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

  /* read til EOL */
  length = 0;
  end=command;
  while ( (c = input()) && c!=EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= 1024) {
      out_err(LEVEL_HIGH,"command is too long (max 1024 chars)\n");
      return 1;
    }
  }
  *end='\0';

  /* skip leading spaces */
  end = command;
  while (*end && (*end==' ' || *end=='\t')) end++;

  if (hook_add_external(&tempConfig.hook,eventmask,end)) return 1;
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
    CFG_SET_DENY_ACCESS_FILES_UPLOADED(&tempConfig);
  else
    CFG_CLEAR_DENY_ACCESS_FILES_UPLOADED(&tempConfig);

  return 0;
}

/* DIR_MESSAGE (string)
*/
int cfg_read_dir_message(void)
{
  char filename[256];
  char c;
  char *end;
  unsigned int token;
  unsigned int length;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'dir_message = ...'\n");
    return 1;
  }

  /* read til EOL */
  length = 0;
  end=filename;
  while ( (c = input()) && c!=EOF && c!='\r' && c!='\n')
  {
    *end++ = c;
    if (++length >= 256) {
      out_err(LEVEL_HIGH,"filename is too long (max 256 chars)\n");
      return 1;
    }
  }
  *end='\0';

  /* skip leading spaces */
  end = filename;
  while (*end && (*end==' ' || *end=='\t')) end++;

  strcpy(tempConfig.dir_message,end);

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
    out_err(LEVEL_FLOOD,"dynamic_ip: NUM (%s)\n",yytext);
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

/* INTERNAL SFV CHECKER (integer)
*/
int cfg_read_internal_sfv(void)
{
  unsigned int token;
  unsigned long l;

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
  while ( (c = input()) && c!=EOF && c!='\r' && c!='\n')
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
  while ( (c = input()) && c!=EOF && c!='\r' && c!='\n')
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

#ifdef DEBUG
  out_err(LEVEL_INFO,"******* setting max_dl_speed : %lu\n",l);
#endif
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
#ifdef DEBUG
  out_err(LEVEL_INFO,"******* changing max_threads: new value %lu\n",l);
#endif
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

#ifdef DEBUG
  out_err(LEVEL_INFO,"******* setting max_ul_speed : %lu\n",l);
#endif
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

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'module = ...'\n");
    return 1;
  }

  if( (token=yylex()) != CFG_ID ) {
    out_err(LEVEL_HIGH,"invalid module name\n");
    return 1;
  }

  if (module_check(yytext)) return 1;
  /* add module to list */
  if (module_add(&tempConfig.module,yytext)) return 1;

  return 0;
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

#ifdef DEBUG
  out_err(LEVEL_INFO,"******* setting pasv_low_range : %lu\n",l);
#endif
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

#ifdef DEBUG
  out_err(LEVEL_INFO,"******* setting pasv_high_range : %lu\n",l);
#endif
  tempConfig.pasv_high_range = l;

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
#ifdef DEBUG
  out_err(LEVEL_INFO,"******* changing port: new value %lu\n",l);
#endif
  tempConfig.port = l;

  return 0;
}

/* SERVER_UID (unsigned int/string)
*/
int cfg_read_server_uid(void)
{
  unsigned int token;
  unsigned long l;
  char *ptr;

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
    return 0;
#ifndef __CYGWIN__
  case CFG_ID:
    { /* not a number, try a login */
      struct passwd * p;
      p = getpwnam(yytext);
      if (!p) {
	out_err(LEVEL_HIGH,"server_uid: could not find uid for user %s\n",yytext);
	return 1;
      }
      wzd_server_uid = p->pw_uid;
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
  { strncpy(tempConfig.site_config.file_ginfo,filename,256); ret = 0; }
  if (strcasecmp("group",type)==0)
  { strncpy(tempConfig.site_config.file_group,filename,256); ret = 0; }
  if (strcasecmp("help",type)==0)
  { strncpy(tempConfig.site_config.file_help,filename,256); ret = 0; }
  if (strcasecmp("rules",type)==0)
  { strncpy(tempConfig.site_config.file_rules,filename,256); ret = 0; }
  if (strcasecmp("swho",type)==0)
  { strncpy(tempConfig.site_config.file_swho,filename,256); ret = 0; }
  if (strcasecmp("user",type)==0)
  { strncpy(tempConfig.site_config.file_user,filename,256); ret = 0; }
  if (strcasecmp("users",type)==0)
  { strncpy(tempConfig.site_config.file_users,filename,256); ret = 0; }
  if (strcasecmp("who",type)==0)
  { strncpy(tempConfig.site_config.file_who,filename,256); ret = 0; }

  free (filename);
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
  sitecmdname = strdup(yytext);
  /* TODO check command unicity ? */

  if( !(command=read_until_eol(1024)) ) {
    out_err(LEVEL_HIGH,"invalid command\n");
    return 1;
  }

  if (hook_add_custom_command(&tempConfig.hook,sitecmdname,command))
  {
    free(sitecmdname);
    free(command);
    return 1;
  }
  free(sitecmdname);
  free(command);
  return 0;
}


/* TLS CERTIFICATE
 * absolute file name
 */
int cfg_read_tls_certificate(void)
{
  unsigned int token;
  char * filename;
  int fd;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'tls_certificate = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

#ifdef SSL_SUPPORT
  fd = open(filename,O_WRONLY | O_CREAT | O_APPEND | O_SYNC,0600);
  if (fd == -1)
    return 1;

  strcpy(tempConfig.tls_certificate,filename);
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* SSL_SUPPORT */

  free(filename);
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

#ifdef SSL_SUPPORT
  strcpy(tempConfig.tls_cipher_list,buffer);
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* SSL_SUPPORT */

  free(buffer);
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

#ifdef SSL_SUPPORT
    if (strcasecmp("explicit",buffer)==0)
      tempConfig.tls_type = TLS_EXPLICIT;
    else if (strcasecmp("explicit_strict",buffer)==0)
      tempConfig.tls_type = TLS_STRICT_EXPLICIT;
    else if (strcasecmp("implicit",buffer)==0)
      tempConfig.tls_type = TLS_IMPLICIT;
    else
    {
      out_err(LEVEL_HIGH,"invalid mode\n");
      free(buffer);
      return 1;
    }
#else
  out_err(LEVEL_INFO,"server compiled without tls support - line ignored\n");
#endif /* SSL_SUPPORT */

  free(buffer);
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
    vfs_add(&tempConfig.vfs,virtual_path,physical_path);
  if (ret) {
    free(buffer);
    out_err(LEVEL_HIGH,"There was a problem adding vfs %s => %s\n",virtual_path,physical_path);
    out_err(LEVEL_HIGH,"Please check destination exists and you have correct permissions\n");
    return 1;
  }

  free(buffer);
  return 0;
}

/* XFERLOG
 * absolute file name
 */
int cfg_read_xferlog(void)
{
  unsigned int token;
  char * filename;
  int fd;

  token = yylex();
  if (token!='=') {
    out_err(LEVEL_HIGH,"line should be 'xferlog = ...'\n");
    return 1;
  }

  if( !(filename=read_until_eol(256)) ) {
    out_err(LEVEL_HIGH,"invalid file name\n");
    return 1;
  }

  fd = open(filename,O_WRONLY | O_CREAT | O_APPEND | O_SYNC,0600);
  if (fd == -1)
    return 1;
  tempConfig.xferlog_name = filename; /* will be freed at server exit */
  tempConfig.xferlog_fd = fd;

  return 0;
}







wzd_config_t * readConfigFile(const char *fileName)
{
/*  char current_token[256];*/
  unsigned int token;
  int ret;

  yyin = fopen(fileName,"r");
  if (!yyin) {
    fprintf(stderr,"Unable to open file\n");
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
	buf = strdup(yytext+strlen("backend_param_"));
        ret = cfg_read_backend_param(buf);
	free(buf);
      }
      break;
    case CFG_CRONJOB:
      ret = cfg_read_cronjob();
      break;
    case CFG_CSCRIPT:
      ret = cfg_read_cscript();
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
    case CFG_INTERNAL_SFV:
      ret = cfg_read_internal_sfv();
      break;
    case CFG_IP:
      ret = cfg_read_ip();
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
    case CFG_PASV_IP:
      ret = cfg_read_pasv_ip();
      break;
    case CFG_PASV_LOW:
      ret = cfg_read_pasv_low();
      break;
    case CFG_PASV_HIGH:
      ret = cfg_read_pasv_high();
      break;
    case CFG_PORT:
      ret = cfg_read_port();
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
	buf = strdup(yytext+strlen("sitefile_"));
        ret = cfg_read_sitefile(buf);
	free(buf);
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
	if (token != CFG_SITE) {
	  out_err(LEVEL_HIGH,"Invalid config line near token %s (%u)\n",yytext,token);
	  continue;
	}
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
	ret = do_permission_line(permission_name,permission_line);
	free(permission_line);
      }
      break;
    default:
      printf("Invalid config line near token %s (%u)\n",yytext,token);
      continue;
    }
  }

  fclose(yyin);
  return &tempConfig;
}

