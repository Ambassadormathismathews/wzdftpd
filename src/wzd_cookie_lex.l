#line 1 "wzd_cookie_lex.l"
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
%x sc_buf
%x sc_cook

%{
#ifdef WIN32
#define        INET_ADDRSTRLEN         16
#define        INET6_ADDRSTRLEN        46
#endif

#if defined(WIN32) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#ifdef __CYGWIN__
#include <w32api/ws2tcpip.h>
#endif

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */

#endif /* __CYGWIN__ && WINSOCK_SUPPORT */

#ifndef WIN32
# include <sys/types.h>
# include <sys/ipc.h>
# include <sys/shm.h>
#endif /* WIN32 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

#include "wzd_cache.h"
#include "wzd_crc32.h"
#include "wzd_messages.h"
#include "wzd_section.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

typedef enum {
  COOKIE=257,
  COOKIE_EOL,
  COOKIE_FOR,
  COOKIE_ENDFOR,
  COOKIE_IF,
  COOKIE_ENDIF,

  COOKIE_INCLUDE,

  COOKIE_INVALID,

  COOKIE_NOCOL,
  COOKIE_BLACK,
  COOKIE_RED,
  COOKIE_GREEN,
  COOKIE_BROWN,
  COOKIE_BLUE,
  COOKIE_MAGENTA,
  COOKIE_CYAN,
  COOKIE_WHITE,

  COOKIE_NEWLINE,

  COOKIE_CONNECTED_MAX,
  COOKIE_CONNECTED_USERS,

  COOKIE_TOTAL_DL,
  COOKIE_TOTAL_DL2,
  COOKIE_TOTAL_UL,
  COOKIE_TOTAL_UL2,

  COOKIE_FILECRC,
  COOKIE_FILEPATH,

  COOKIE_GROUPHOME,
  COOKIE_GROUPID,
  COOKIE_GROUPIP_ALLOW,
  COOKIE_GROUPMAXDL,
  COOKIE_GROUPMAXIDLE,
  COOKIE_GROUPMAXUL,
  COOKIE_GROUPNAME,
  COOKIE_GROUPNUM_LOGINS,
  COOKIE_GROUPRATIO,
  COOKIE_GROUPTAG,
  COOKIE_GROUPTOTAL_DL,
  COOKIE_GROUPTOTAL_DL2,
  COOKIE_GROUPTOTAL_UL,
  COOKIE_GROUPTOTAL_UL2,

  COOKIE_LASTFILENAME,
  COOKIE_LASTFILESIZE,
  COOKIE_LASTFILESPEED,
  COOKIE_LASTFILETIME,

  COOKIE_MSG,

  COOKIE_SECTIONNAME,

  COOKIE_SPACEFREE,
  COOKIE_SPACETOTAL,

  COOKIE_USERCREDITS,
  COOKIE_USERCREDITS2,
  COOKIE_USERFILES_DL,
  COOKIE_USERFILES_UL,
  COOKIE_USERFLAGS,
  COOKIE_USERGROUP,
  COOKIE_USERGROUPS,
  COOKIE_USERHOME,
  COOKIE_USERID,
  COOKIE_USERIP,
  COOKIE_USERIP_ALLOW,
  COOKIE_USERLASTCMD,
  COOKIE_USERLAST_LOGIN,
  COOKIE_USERLEECHSLOTS,
  COOKIE_USERMAXDL,
  COOKIE_USERMAXIDLE,
  COOKIE_USERMAXUL,
  COOKIE_USERNAME,
  COOKIE_USERNUM_LOGINS,
  COOKIE_USERPATH,
  COOKIE_USERPID,
  COOKIE_USERPWD,
  COOKIE_USERRATIO,
  COOKIE_USERSLOTS,
  COOKIE_USERSPEED,
  COOKIE_USERTAG,
  COOKIE_USERTIME,
  COOKIE_USERTOTAL_DL,
  COOKIE_USERTOTAL_DL2,
  COOKIE_USERTOTAL_UL,
  COOKIE_USERTOTAL_UL2,

  COOKIE_VFSVIRTUAL,
  COOKIE_VFSPHYSICAL,
  COOKIE_VFSTARGET,
} sc_cookie_t;

/* this var defines a 'prefered' minimal buffer size before sending */
#define MIN_SEND_BUFFERSIZE	500
#define MAX_SEND_BUFFERSIZE	4096

#define MAX_LOOP_DEPTH	10
char * loop_buffer[MAX_LOOP_DEPTH];
int loop_buffer_type[MAX_LOOP_DEPTH];
int loop_buffer_ptr=0;

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int cookie_include_stack_ptr = 0;

#define IBUFSIZE	4096

wzd_user_t * current_user=NULL;
wzd_group_t * current_group=NULL;
wzd_context_t * current_context=NULL;
wzd_vfs_t * current_vfs=NULL;

%}

DIGIT [0-9]
LETTER  [a-zA-Z]

LF		\x0A
CR		\x0D
NL		{CR}*{LF}

FOR_BEGIN	"%for("{LETTER}+")"{NL}
FOR_END		"%endfor"{NL}

IF_BEGIN	"%if("("+"|"=")?{LETTER}+")"{NL}
IF_END		"%endif"{NL}

C_START		"%"
C_BW		([0-9]+".")?"bw"
C_CONN		([0-9]+".")?"connected_"
C_FILE		([0-9]+".")?"file"
C_GROUP		([0-9]+".")?"group"
C_LASTFILE	([0-9]+".")?"lastfile"
C_USER		([0-9]+".")?"user"
C_VFS    ([0-9]+".")?"vfs"

%option nounput
%option noyywrap
/*%option debug*/
%option never-interactive
%option prefix="cookie"
%option outfile="lex.yy.c"
%%

<INITIAL>\r		/* ignore */
<INITIAL>\n		return COOKIE_EOL;

<INITIAL>{FOR_BEGIN}	{
  BEGIN(sc_buf);
  if (loop_buffer_ptr >= MAX_LOOP_DEPTH){
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Loops nested too deeply\n" );
#endif
    return 0;
  }
  loop_buffer_type[loop_buffer_ptr++] = COOKIE_FOR;
  return COOKIE_FOR;
}
<INITIAL>{IF_BEGIN}	{
  BEGIN(sc_buf);
  if (loop_buffer_ptr >= MAX_LOOP_DEPTH){
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Loops nested too deeply\n" );
#endif
    return 0;
  }
  loop_buffer_type[loop_buffer_ptr++] = COOKIE_IF;
  return COOKIE_IF;
}

<INITIAL>{FOR_END}	return COOKIE_ENDFOR;
<INITIAL>{IF_END}	return COOKIE_ENDIF;

<sc_buf>{FOR_BEGIN}	{
  if (loop_buffer_ptr >= MAX_LOOP_DEPTH){
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Loops nested too deeply\n" );
#endif
    return 0;
  }
  loop_buffer_type[loop_buffer_ptr++] = COOKIE_FOR;
  return COOKIE_FOR;
}
<sc_buf>{FOR_END}	{
  --loop_buffer_ptr;
  if (loop_buffer_type[loop_buffer_ptr] != COOKIE_FOR) {
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Unexpected %%endfor\n" );
#endif
    return 0;
  }
  if (loop_buffer_ptr)
    return *yytext;
  else
    return COOKIE_ENDFOR;
}
<sc_buf>{IF_BEGIN}	{
  if (loop_buffer_ptr >= MAX_LOOP_DEPTH){
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Loops nested too deeply\n" );
#endif
    return 0;
  }
  loop_buffer_type[loop_buffer_ptr++] = COOKIE_IF;
  return COOKIE_IF;
}
<sc_buf>{IF_END}	{
  --loop_buffer_ptr;
  if (loop_buffer_type[loop_buffer_ptr] != COOKIE_IF) {
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Unexpected %%endif\n" );
#endif
    return 0;
  }
  if (loop_buffer_ptr)
    return *yytext;
  else
    return COOKIE_ENDIF;
}

<sc_buf>%	return '%';
<sc_buf>([^%]|[ \r\n])*	return *yytext;

{C_START}	BEGIN(sc_cook);
<sc_cook>%	BEGIN(INITIAL); return '%';
<sc_cook>!0	BEGIN(INITIAL); return COOKIE_NOCOL;
<sc_cook>!black	BEGIN(INITIAL); return COOKIE_BLACK;
<sc_cook>!red	BEGIN(INITIAL); return COOKIE_RED;
<sc_cook>!green	BEGIN(INITIAL); return COOKIE_GREEN;
<sc_cook>!brown	BEGIN(INITIAL); return COOKIE_BROWN;
<sc_cook>!blue	BEGIN(INITIAL); return COOKIE_BLUE;
<sc_cook>!magenta	BEGIN(INITIAL); return COOKIE_MAGENTA;
<sc_cook>!cyan	BEGIN(INITIAL); return COOKIE_CYAN;
<sc_cook>!white	BEGIN(INITIAL); return COOKIE_WHITE;

<sc_cook>{C_BW}total_dl2	BEGIN(INITIAL); return COOKIE_TOTAL_DL2;
<sc_cook>{C_BW}total_dl		BEGIN(INITIAL); return COOKIE_TOTAL_DL;
<sc_cook>{C_BW}total_ul2	BEGIN(INITIAL); return COOKIE_TOTAL_UL2;
<sc_cook>{C_BW}total_ul		BEGIN(INITIAL); return COOKIE_TOTAL_UL;

<sc_cook>{C_CONN}maxusers	BEGIN(INITIAL); return COOKIE_CONNECTED_MAX;
<sc_cook>{C_CONN}users		BEGIN(INITIAL); return COOKIE_CONNECTED_USERS;

<sc_cook>{C_FILE}crc		BEGIN(INITIAL); return COOKIE_FILECRC;
<sc_cook>{C_FILE}path		BEGIN(INITIAL); return COOKIE_FILEPATH;

<sc_cook>{C_GROUP}home		BEGIN(INITIAL); return COOKIE_GROUPHOME;
<sc_cook>{C_GROUP}id		BEGIN(INITIAL); return COOKIE_GROUPID;
<sc_cook>{C_GROUP}ip_allow[0-9]+	BEGIN(INITIAL); return COOKIE_GROUPIP_ALLOW;
<sc_cook>{C_GROUP}maxdl		BEGIN(INITIAL); return COOKIE_GROUPMAXDL;
<sc_cook>{C_GROUP}maxidle	BEGIN(INITIAL); return COOKIE_GROUPMAXIDLE;
<sc_cook>{C_GROUP}maxul		BEGIN(INITIAL); return COOKIE_GROUPMAXUL;
<sc_cook>{C_GROUP}name		BEGIN(INITIAL); return COOKIE_GROUPNAME;
<sc_cook>{C_GROUP}num_logins	BEGIN(INITIAL); return COOKIE_GROUPNUM_LOGINS;
<sc_cook>{C_GROUP}ratio		BEGIN(INITIAL); return COOKIE_GROUPRATIO;
<sc_cook>{C_GROUP}tag		BEGIN(INITIAL); return COOKIE_GROUPTAG;
<sc_cook>{C_GROUP}total_dl2	BEGIN(INITIAL); return COOKIE_GROUPTOTAL_DL2;
<sc_cook>{C_GROUP}total_dl	BEGIN(INITIAL); return COOKIE_GROUPTOTAL_DL;
<sc_cook>{C_GROUP}total_ul2	BEGIN(INITIAL); return COOKIE_GROUPTOTAL_UL2;
<sc_cook>{C_GROUP}total_ul	BEGIN(INITIAL); return COOKIE_GROUPTOTAL_UL;

<sc_cook>{C_LASTFILE}name	BEGIN(INITIAL); return COOKIE_LASTFILENAME;
<sc_cook>{C_LASTFILE}size	BEGIN(INITIAL); return COOKIE_LASTFILESIZE;
<sc_cook>{C_LASTFILE}speed	BEGIN(INITIAL); return COOKIE_LASTFILESPEED;
<sc_cook>{C_LASTFILE}time	BEGIN(INITIAL); return COOKIE_LASTFILETIME;

<sc_cook>msg                    BEGIN(INITIAL); return COOKIE_MSG;

<sc_cook>sectionname            BEGIN(INITIAL); return COOKIE_SECTIONNAME;
<sc_cook>spacefree              BEGIN(INITIAL); return COOKIE_SPACEFREE;
<sc_cook>spacetotal             BEGIN(INITIAL); return COOKIE_SPACETOTAL;

<sc_cook>{C_USER}credits2	BEGIN(INITIAL); return COOKIE_USERCREDITS2;
<sc_cook>{C_USER}credits	BEGIN(INITIAL); return COOKIE_USERCREDITS;
<sc_cook>{C_USER}files_dl	BEGIN(INITIAL); return COOKIE_USERFILES_DL;
<sc_cook>{C_USER}files_ul	BEGIN(INITIAL); return COOKIE_USERFILES_UL;
<sc_cook>{C_USER}flags		BEGIN(INITIAL); return COOKIE_USERFLAGS;
<sc_cook>{C_USER}groups		BEGIN(INITIAL); return COOKIE_USERGROUPS;
<sc_cook>{C_USER}group		BEGIN(INITIAL); return COOKIE_USERGROUP;
<sc_cook>{C_USER}home		BEGIN(INITIAL); return COOKIE_USERHOME;
<sc_cook>{C_USER}id		BEGIN(INITIAL); return COOKIE_USERID;
<sc_cook>{C_USER}ip_allow[0-9]+	BEGIN(INITIAL); return COOKIE_USERIP_ALLOW;
<sc_cook>{C_USER}ip		BEGIN(INITIAL); return COOKIE_USERIP;
<sc_cook>{C_USER}lastcmd	BEGIN(INITIAL); return COOKIE_USERLASTCMD;
<sc_cook>{C_USER}last_login	BEGIN(INITIAL); return COOKIE_USERLAST_LOGIN;
<sc_cook>{C_USER}leechslots	BEGIN(INITIAL); return COOKIE_USERLEECHSLOTS;
<sc_cook>{C_USER}maxdl		BEGIN(INITIAL); return COOKIE_USERMAXDL;
<sc_cook>{C_USER}maxidle	BEGIN(INITIAL); return COOKIE_USERMAXIDLE;
<sc_cook>{C_USER}maxul		BEGIN(INITIAL); return COOKIE_USERMAXUL;
<sc_cook>{C_USER}name		BEGIN(INITIAL); return COOKIE_USERNAME;
<sc_cook>{C_USER}num_logins	BEGIN(INITIAL); return COOKIE_USERNUM_LOGINS;
<sc_cook>{C_USER}path		BEGIN(INITIAL); return COOKIE_USERPATH;
<sc_cook>{C_USER}pid		BEGIN(INITIAL); return COOKIE_USERPID;
<sc_cook>{C_USER}pwd		BEGIN(INITIAL); return COOKIE_USERPWD;
<sc_cook>{C_USER}ratio		BEGIN(INITIAL); return COOKIE_USERRATIO;
<sc_cook>{C_USER}slots		BEGIN(INITIAL); return COOKIE_USERSLOTS;
<sc_cook>{C_USER}speed		BEGIN(INITIAL); return COOKIE_USERSPEED;
<sc_cook>{C_USER}tag		BEGIN(INITIAL); return COOKIE_USERTAG;
<sc_cook>{C_USER}time		BEGIN(INITIAL); return COOKIE_USERTIME;
<sc_cook>{C_USER}total_dl2	BEGIN(INITIAL); return COOKIE_USERTOTAL_DL2;
<sc_cook>{C_USER}total_dl	BEGIN(INITIAL); return COOKIE_USERTOTAL_DL;
<sc_cook>{C_USER}total_ul2	BEGIN(INITIAL); return COOKIE_USERTOTAL_UL2;
<sc_cook>{C_USER}total_ul	BEGIN(INITIAL); return COOKIE_USERTOTAL_UL;
<sc_cook>{C_VFS}virtual  BEGIN(INITIAL); return COOKIE_VFSVIRTUAL;
<sc_cook>{C_VFS}physical  BEGIN(INITIAL); return COOKIE_VFSPHYSICAL;
<sc_cook>{C_VFS}target  BEGIN(INITIAL); return COOKIE_VFSTARGET;

<sc_cook>include         BEGIN(INITIAL); return COOKIE_INCLUDE;

<sc_cook>.	BEGIN(INITIAL); return COOKIE_INVALID;

.		return *yytext;

%%

void get_cookie_format(const char *cookie, int * padding)
{
  unsigned long l;
  char *ptr;

  *padding = 0;

  l=strtoul(cookie,&ptr,10);
  if (*ptr == '.') { /* test should have been done by lexical analyser */
    if (l <= 5000) /* FIXME hardcoded limit */
      *padding = l;
  }
}

int cookie_parse_buffer(const char *buffer, wzd_user_t * user, wzd_group_t * group,
wzd_context_t * context, char * out_buffer, unsigned int out_buffer_len)
{
  wzd_user_t * me = NULL;
  char send_buffer[MAX_SEND_BUFFERSIZE];
  char internalbuffer[IBUFSIZE];
  char condition[256];
  unsigned int length;
  unsigned int cookie;
  int i, padding;
  char * cookie_ptr = NULL;
  int cookie_length;
  int convert=0;
  float val;
  char c;
  u64_t total;
  unsigned int send_buffer_ptr=0;
  unsigned short use_colors=0;
  char * out_buffer_ptr;
  wzd_context_t * real_context;
  wzd_context_t * loop_context;
  ListElmt * elmnt;

/*  if (!context) return -1;*/ /* XXX this prevent using the function from cron jobs ! */
  real_context = GetMyContext();
/*  if (!real_context) return -1;*/ /* XXX this prevent using the function from cron jobs ! */
  if (real_context)
    me = GetUserByID(real_context->userid);
/*  if (!me) return -1;*/

  if (me && me->flags && strchr(me->flags,FLAG_COLOR)) use_colors=1;

  if ( cookie_include_stack_ptr >= MAX_INCLUDE_DEPTH )
  {
#ifdef WZD_DBG_COOKIES
    out_err(LEVEL_HIGH, "Includes nested too deeply" );
#endif
    return -1;
  }
  if (cookie_include_stack_ptr)
    include_stack[cookie_include_stack_ptr] = YY_CURRENT_BUFFER;
  cookie_include_stack_ptr++;
  yy_switch_to_buffer(yy_scan_string(buffer));

  current_context = context;
  current_user = user;
  current_group = group;

  if (out_buffer) *out_buffer = '\0';
  out_buffer_ptr = out_buffer;

  while ( (cookie=yylex()) )
  {
    cookie_ptr = NULL;
    cookie_length = 0;
    padding = 0;
    switch(cookie) {
    case COOKIE_IF:
    {
      char * tmpbuf;
      chop(yytext);
      length = strlen(yytext);
      if (length<5 || length>=256)
      {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH, "Invalid if loop\n" );
#endif
        return 1;
      }
      memcpy(condition,yytext+4,length-5); /* 5 = strlen("%if()"= */
      condition[length-5]='\0';
      i=0;
      tmpbuf = malloc(16384);
#if 0
out_err(LEVEL_HIGH,"AAAAAAAAAAAAAAAA\n");
      {
        char c;
        while ( (c= input()) && c != EOF && (c == '\r' || c == '\n'))
        {
out_err(LEVEL_HIGH,"char: %d [%c]\n", c, c);
          /* eat EOL */
        }
      }
#endif
/*      printf("starting if loop (%s)\n",condition);*/
      while ((cookie=yylex()) && cookie!=COOKIE_ENDIF)
      {
        /*	if (i>=LOOP_MAX_LINES) {
                printf("too much lines in for loop (max %d\n)",LOOP_MAX_LINES);
                return 1;
                }*/
        while (yytext[0] && (yytext[0] == '\r' || yytext[0] == '\n')) yytext++;
        if ( (i+strlen(yytext)) >= 16384 ) {
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH, "loop TOO LONG !\n" );
#endif
          exit(1);
        }
        strcpy(tmpbuf+i,yytext);
/*        printf("%s[31mMARK[0m\n",yytext);*/
        i+=strlen(yytext);
      }
      if (cookie) {
/*        printf("End of if loop (i=%d)\n",i);*/
        BEGIN(INITIAL);
      } else {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH, "unterminated if loop\n" );
#endif
        free(tmpbuf);
        return 1;
      }
      /* flush buffer before executing 'for' loop */
/*      printf("flushing buffer on [31mIF[0m\n");*/
      /* flush buffer */
      if (out_buffer) {
        unsigned int l = send_buffer_ptr;
        if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH,"buffer truncated !");
#endif
          l = out_buffer_len - 1;
        }
        memcpy(out_buffer_ptr,send_buffer,l);
        out_buffer_ptr[l] = '\0';
        out_buffer_ptr += l;
      } else {
        send_buffer[send_buffer_ptr]='\0';
        if (real_context)
          send_message_raw(send_buffer,real_context);
        send_buffer_ptr=0;
      }
      /* test if() condition */
      /* TODO XXX FIXME more checks needed ! */
      if (condition[0] == '+') {
        WZD_ASSERT( (current_user != NULL) );
        if (current_user && current_user->flags && strchr(user->flags,condition[1]))
          cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
      }
      free(tmpbuf);
    }
    break;
    case COOKIE_FOR:
    {
      char * tmpbuf;
      chop(yytext);
      length = strlen(yytext);
      if (length<7 || length>=256)
      {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"invalid for loop");
#endif
        return 1;
      }
      memcpy(condition,yytext+5,length-6); /* 6 = strlen("%for()") */
      condition[length-6]='\0';
      i=0;
      tmpbuf = malloc(16384);
/*      printf("starting for loop (%s)\n",condition);*/
      while ((cookie=yylex()) && cookie!=COOKIE_ENDFOR)
      {
        /*	if (i>=LOOP_MAX_LINES) {
                printf("too much lines in for loop (max %d\n)",LOOP_MAX_LINES);
                return 1;
                }*/
        if ( (i+strlen(yytext)) >= 16384 ) {
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH,"loop TOO LONG !");
#endif
          exit(1);
        }
        while (yytext[0] && (yytext[0] == '\r' || yytext[0] == '\n')) yytext++;
        strcpy(tmpbuf+i,yytext);
/*        printf("%s[31mMARK[0m\n",yytext);*/
        i+=strlen(yytext);
      }
      if (cookie) {
/*        printf("End of for loop (i=%d)\n",i);*/
        BEGIN(INITIAL);
      } else {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"unterminated for loop");
#endif
        return 1;
      }
      /* flush buffer before executing 'for' loop */
/*      printf("flushing buffer on [31mFOR[0m\n");*/
      /* flush buffer */
      if (out_buffer) {
        unsigned int l = send_buffer_ptr;
        if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH,"buffer truncated !");
#endif
          l = out_buffer_len - 1;
        }
        memcpy(out_buffer_ptr,send_buffer,l);
        out_buffer_ptr[l] = '\0';
        out_buffer_ptr += l;
      } else {
        send_buffer[send_buffer_ptr]='\0';
        if (real_context)
          send_message_raw(send_buffer,real_context);
        send_buffer_ptr=0;
      }
      /* execute for loop */
      if (strcmp(condition,"allusersconnected")==0)
      {
        wzd_user_t * loop_user;
        for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
        {
          loop_context = list_data(elmnt);
          if (loop_context->magic == CONTEXT_MAGIC)
          {
            loop_user = GetUserByID(loop_context->userid);
            current_user = loop_user;
            current_context = loop_context;
            if (loop_user && loop_user->username[0] != '\0') {
              /* check if user is hidden */
              if (loop_user->flags && strchr(loop_user->flags,FLAG_HIDDEN)
                  && (me)
                  && !strchr(me->flags,FLAG_SITEOP)
                  && strcmp(loop_user->username,me->username)!=0) /* do not hide to self ! */
                continue;
            }
            if (out_buffer)
              cookie_parse_buffer(tmpbuf,loop_user,current_group,current_context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
            else
              cookie_parse_buffer(tmpbuf,loop_user,current_group,current_context,out_buffer_ptr,0);
          }
        }
        current_user = user;
        current_context = NULL;
      } /* allusersconnected */
      else if (strcmp(condition,"allusers")==0)
      {
        wzd_user_t * loop_user;
        uid_t * uid_list;
        uid_list = (uid_t*)backend_get_user(-2);
        if (uid_list) {
          for (i=0; uid_list[i] != (uid_t)-1; i++)
          {
            loop_user = GetUserByID(uid_list[i]);
            current_user = loop_user;
            if (loop_user && loop_user->username[0] != '\0') {
              if (out_buffer)
                cookie_parse_buffer(tmpbuf,loop_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
              else
                cookie_parse_buffer(tmpbuf,loop_user,current_group,context,out_buffer_ptr,0);
            }
          }
          current_user = user;
          wzd_free(uid_list);
        }
      } /* allusers */
      else if (strcmp(condition,"allgroups")==0)
      {
        wzd_group_t * loop_group;
        gid_t * gid_list;
        gid_list = (gid_t*)backend_get_group(-2);
        if (gid_list) {
          for (i=0; gid_list[i] != (gid_t)-1; i++)
          {
            loop_group = GetGroupByID(gid_list[i]);
            current_group = loop_group;
            if (loop_group && loop_group->groupname[0] != '\0') {
              if (out_buffer)
                cookie_parse_buffer(tmpbuf,current_user,loop_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
              else
                cookie_parse_buffer(tmpbuf,current_user,loop_group,context,out_buffer_ptr,0);
            }
          }
          current_group = group;
          wzd_free(gid_list);
        }
      } /* allgroups */
      else if (strcmp(condition,"allgroupmembers")==0)
      {
        wzd_user_t * loop_user;
        gid_t gid;
        if (current_group) {
          uid_t * uid_list;

          uid_list = (uid_t*)backend_get_user(-2);
          if (uid_list) {
            gid = GetGroupIDByName(current_group->groupname);
            for (i=0; uid_list[i] != (uid_t)-1; i++)
            {
              loop_user = GetUserByID(uid_list[i]);
              current_user = loop_user;
              if (loop_user && loop_user->username[0] != '\0' && is_user_in_group(loop_user,gid)==1) {
                if (out_buffer)
                  cookie_parse_buffer(tmpbuf,loop_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
                else
                  cookie_parse_buffer(tmpbuf,loop_user,current_group,context,out_buffer_ptr,0);
              }
            }
            wzd_free(uid_list);
          }
          current_user = user;
        }
      } /* allgroupmembers */
      else if (strcmp(condition,"allvfs")==0)
      {
        current_vfs = mainConfig->vfs;
        while(current_vfs)
        {
          if (out_buffer)
            cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
          else
            cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,0);
          current_vfs = current_vfs->next_vfs;
        }
      } /* allvfs */
      free(tmpbuf);
    }
    break;
    case COOKIE_INCLUDE:
    {
      wzd_cache_t * fp;
      char * tmpbuf;
      char filename[256];
      char c;
      unsigned int i=0;

      c = input();
      if (c != '(')
      {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH, "invalid 'include' directive\n");
#endif
        break;
      }

      while ( (c=input()) && c != ')' && c != '\r' && c != '\n' && i < sizeof(filename))
        filename[i++] = c;
      if (c != ')') /* error */
        break;
      filename[i] = '\0';

#ifdef WZD_DBG_COOKIES
      out_err(LEVEL_HIGH,"  including [%s]\n", filename);
#endif

      /** \todo resolve realpath() before opening filename ? */
      fp = wzd_cache_open(filename, O_RDONLY, 0);
      if (!fp)
      {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH, "invalid 'include' directive (could not open file)\n");
#endif
        break; /* invalid file name */
      }

      i = wzd_cache_getsize(fp);
      tmpbuf = wzd_malloc(i+1);
      if (wzd_cache_read(fp, tmpbuf, i) != (int)i) {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH, "invalid 'include' directive (error reading file)\n");
#endif
        wzd_free(tmpbuf);
        wzd_cache_close(fp);
        break;
      }
      wzd_cache_close(fp);
      tmpbuf[i] = '\0';


      /* flush buffer before executing 'include' */
#ifdef WZD_DBG_COOKIES
      out_log(LEVEL_HIGH,"flushing buffer on [31mINCLUDE[0m\n");
#endif
      /* flush buffer */
      if (out_buffer) {
        unsigned int l = send_buffer_ptr;
        if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH,"buffer truncated !");
#endif
          l = out_buffer_len - 1;
        }
        memcpy(out_buffer_ptr,send_buffer,l);
        out_buffer_ptr[l] = '\0';
        out_buffer_ptr += l;
        send_buffer_ptr=0; /** \todo XXX i added this line, wasn'r present - could be a bug in all
        other flushes (FOR, etc ?! */
      } else {
        send_buffer[send_buffer_ptr]='\0';
        if (real_context)
          send_message_raw(send_buffer,real_context);
        send_buffer_ptr=0;
      }

      if (out_buffer) {
        cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));

        i = strlen(out_buffer_ptr);
        if (send_buffer_ptr + i >= sizeof(send_buffer)) {
          out_log(LEVEL_HIGH, "Buffer overflow\n");
          return 1;
        }
        memcpy(send_buffer+send_buffer_ptr, out_buffer_ptr, i);
        send_buffer_ptr += i;
      }
      else
        cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,0);

      wzd_free(tmpbuf);

      BEGIN(INITIAL);
    }
    break;
/*** Bandwidth cookies ***/
    case COOKIE_TOTAL_DL2:
      convert=1;
    case COOKIE_TOTAL_DL:
      get_cookie_format(yytext,&padding);
      {
        float speed;
        wzd_context_t * it;

        /* iterate through users and sum */
        speed = 0.f;
        for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
        {
          it = list_data(elmnt);
          if (it->magic == CONTEXT_MAGIC)
          {
            if (strncasecmp(it->last_command,"retr",4)==0)
              speed += it->current_dl_limiter.current_speed;
          }
        }
        if (convert) {
          bytes_to_unit(&speed,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c/s",speed,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%.2f",speed);
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
    case COOKIE_TOTAL_UL2:
      convert=1;
    case COOKIE_TOTAL_UL:
      get_cookie_format(yytext,&padding);
      {
        float speed;
        wzd_context_t * it;

        /* iterate through users and sum */
        speed = 0.f;
        for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
        {
          it = list_data(elmnt);
          if (it->magic == CONTEXT_MAGIC)
          {
            if ((strncasecmp(it->last_command,"stor",4)==0) ||
                (strncasecmp(it->last_command,"appe",4)==0))
              speed += it->current_ul_limiter.current_speed;
          }
        }
        if (convert) {
          bytes_to_unit(&speed,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c/s",speed,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%.2f",speed);
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
/*** Connecte users cookies ***/
    case COOKIE_CONNECTED_MAX:
      snprintf(internalbuffer,IBUFSIZE,"%d",mainConfig->max_threads);
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_CONNECTED_USERS:
      get_cookie_format(yytext,&padding);
      {
        unsigned int count=0;

        for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
        {
          loop_context = list_data(elmnt);
          if (loop_context->magic == CONTEXT_MAGIC)
            count++;
        }
        snprintf(internalbuffer,IBUFSIZE,"%d",count);
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
/*** FILE cookies ***/
    case COOKIE_FILECRC:
      get_cookie_format(yytext,&padding);
      if (context) {
        unsigned long crc=0;
        if ((context->current_action.token == TOK_RETR ||
        context->current_action.token == TOK_STOR ||
        context->current_action.token == TOK_APPE) &&
        (!calc_crc32(context->current_action.arg,&crc,0,(unsigned long)-1)))
        {
          snprintf(internalbuffer,IBUFSIZE,"%lX",crc);
        }
        else
          snprintf(internalbuffer,IBUFSIZE,"0");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"filecrc");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_FILEPATH:
      get_cookie_format(yytext,&padding);
      if (context) {
        switch (context->current_action.token) {
        case TOK_RETR:
        case TOK_STOR:
        case TOK_APPE:
          snprintf(internalbuffer,IBUFSIZE,"%s",context->current_action.arg);
          break;
        case TOK_MKD:
        case TOK_DELE:
          snprintf(internalbuffer,IBUFSIZE,"%s",context->current_action.arg);
          break;
        default:
          snprintf(internalbuffer,IBUFSIZE,"(null)");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"filepath");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
/*** GROUP cookies ***/
    case COOKIE_GROUPHOME:
      get_cookie_format(yytext,&padding);
      if (current_group)
        snprintf(internalbuffer,IBUFSIZE,"%s",current_group->defaultpath);
      else
        snprintf(internalbuffer,IBUFSIZE,"grouphome");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPID:
      get_cookie_format(yytext,&padding);
      if (current_group)
        snprintf(internalbuffer,IBUFSIZE,"%u",current_group->gid);
      else
        snprintf(internalbuffer,IBUFSIZE,"groupid");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPIP_ALLOW:
      get_cookie_format(yytext,&padding);
      {
        unsigned long index;
        char *ptr;
        char *numstart;
        /* we can suppress check here, flex has already done his work */
        numstart = yytext+strlen(yytext)-1;
        while ( isdigit(*(numstart-1)) ) numstart--;
        index = strtoul(numstart,&ptr,10);
        if (index<HARD_IP_PER_GROUP)
        {
          if (current_group)
            snprintf(internalbuffer,IBUFSIZE,"%s",current_group->ip_allowed[index]);
          else
            snprintf(internalbuffer,IBUFSIZE,"usergroup_allow");
        } else {
          snprintf(internalbuffer,IBUFSIZE,"invalid index");
        }
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPMAXDL:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_group->max_dl_speed);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"groupmaxdl");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPMAXIDLE:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_group->max_idle_time);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"groupmaxidle");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPMAXUL:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_group->max_ul_speed);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"groupmaxul");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
     case COOKIE_GROUPNAME:
      get_cookie_format(yytext,&padding);
      if (current_group)
        snprintf(internalbuffer,IBUFSIZE,"%s",current_group->groupname);
      else
        snprintf(internalbuffer,IBUFSIZE,"groupname");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPNUM_LOGINS:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        snprintf(internalbuffer,IBUFSIZE,"%d",current_group->num_logins);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"groupnum_logins");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPRATIO:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        if (current_group->ratio)
          snprintf(internalbuffer,IBUFSIZE,"1:%u",current_group->ratio);
        else
          snprintf(internalbuffer,IBUFSIZE,"unlimited");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"groupratio");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPTAG:
      get_cookie_format(yytext,&padding);
      if (current_group) {
        if (strlen(current_group->tagline)>0)
          snprintf(internalbuffer,IBUFSIZE,"%s",current_group->tagline);
        else
          snprintf(internalbuffer,IBUFSIZE,"no tagline set");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"grouptag");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_GROUPTOTAL_DL2:
      convert=1;
    case COOKIE_GROUPTOTAL_DL:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        int gid;
        wzd_user_t * loop_user;
        int * uid_list;
        /* iterate through users and sum */
        gid = GetGroupIDByName(current_group->groupname);
        total = 0;
        uid_list = (int*)backend_get_user(-2);
        if (uid_list) {
          for (i=0; uid_list[i] >= 0; i++)
          {
            loop_user = GetUserByID(uid_list[i]);
            if (!loop_user) continue;
            if (is_user_in_group(loop_user,gid)==1)
            {
              total += loop_user->stats.bytes_dl_total;
            }
          }
          wzd_free(uid_list);
        }
        if (convert) {
#ifndef _MSC_VER
          val = (float)total;
#else
          val = (float)(__int64)total;
#endif
          bytes_to_unit(&val,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c",val,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%lld",total);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"grouptotal_dl");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
    case COOKIE_GROUPTOTAL_UL2:
      convert=1;
    case COOKIE_GROUPTOTAL_UL:
      get_cookie_format(yytext,&padding);
      if (current_group)
      {
        int gid;
        wzd_user_t * loop_user;
        int * uid_list;
        /* iterate through users and sum */
        gid = GetGroupIDByName(current_group->groupname);
        total = 0;
        uid_list = (int*)backend_get_user(-2);
        if (uid_list) {
          for (i=0; uid_list[i] >= 0; i++)
          {
            loop_user = GetUserByID(uid_list[i]);
            if (!loop_user) continue;
            if (is_user_in_group(loop_user,gid)==1)
            {
              total += loop_user->stats.bytes_ul_total;
            }
          }
          wzd_free(uid_list);
        }
        if (convert) {
#ifndef _MSC_VER
          val = (float)total;
#else
          val = (float)(__int64)total;
#endif
          bytes_to_unit(&val,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c",val,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%lld",total);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"grouptotal_ul");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
/*** LAST FILE cookies ***/
    case COOKIE_LASTFILENAME:
      get_cookie_format(yytext,&padding);
      if (context) {
        switch (context->last_file.token) {
        case TOK_RETR:
        case TOK_STOR:
        case TOK_APPE:
          snprintf(internalbuffer,IBUFSIZE,"%s",context->last_file.name);
          break;
        case TOK_MKD:
          snprintf(internalbuffer,IBUFSIZE,"%s",context->last_file.name);
          break;
        default:
          snprintf(internalbuffer,IBUFSIZE,"(null)");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"lastfilename");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_LASTFILESIZE:
      get_cookie_format(yytext,&padding);
      if (context)
        /* use 64 bits here */
        snprintf(internalbuffer,IBUFSIZE,"%" PRIu64,(context->last_file.name[0]!='\0')?context->last_file.size:0);
      else
        snprintf(internalbuffer,IBUFSIZE,"lastfilesize");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_LASTFILESPEED:
      get_cookie_format(yytext,&padding);
      if (context)
      {
	    float f, time;
#ifndef _MSC_VER
        f = (float)context->last_file.size;
#else
        f = (float)(__int64)context->last_file.size;
#endif
        if (context->last_file.name[0]!='\0')
        {
          time = (float)context->last_file.tv.tv_sec + ((float)context->last_file.tv.tv_usec/1000000.f);
          /** convert to kB/s ? */
          snprintf(internalbuffer,IBUFSIZE,"%.1f",
            ((time > 1e-5) ? (f / time) : 0.f) / 1024.f
            );
        }
        else
          snprintf(internalbuffer,IBUFSIZE,"0");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"lastfilespeed");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_LASTFILETIME:
      get_cookie_format(yytext,&padding);
      if (context)
        snprintf(internalbuffer,IBUFSIZE,"%.4f",(context->last_file.name[0]!='\0')?
        (float)context->last_file.tv.tv_sec + ((float)context->last_file.tv.tv_usec/1000000.f) :0);
      else
        snprintf(internalbuffer,IBUFSIZE,"lastfiletime");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
/*** FILES cookies ***/
    case COOKIE_MSG:
    {
      wzd_cache_t * file;
      char * tmpbuf;
      char buffer[IBUFSIZE];
      int length;
      unsigned int size;

      if (!mainConfig->dir_message) {
        cookie_ptr = internalbuffer;
        cookie_length = 0;
        break;
      }

      if (checkpath_new(".",buffer,context)) {
        snprintf(internalbuffer,IBUFSIZE,"Could not get current path");
        cookie_ptr = internalbuffer;
        cookie_length = strlen(cookie_ptr);
        break;
      } else {
        length = strlen(buffer);
        if (buffer[length-1] != '/') buffer[length++] = '/';
        strncpy(buffer+length,mainConfig->dir_message,IBUFSIZE-length-1);
        file = wzd_cache_open(buffer,O_RDONLY,0666);
        if (!file) {
          cookie_ptr = NULL;
          cookie_length = 0;
          break;
        }
        size = wzd_cache_getsize(file);
        if (size >= out_buffer_len) { /* is it a good condition ? */
#ifdef WZD_DBG_COOKIES
          out_err(LEVEL_HIGH,"buffer truncated !");
#endif
          size = out_buffer_len - size;
        }
        tmpbuf = wzd_malloc(size+1);
        wzd_cache_read(file,tmpbuf,size);
        tmpbuf[size] = '\0';
        wzd_cache_close(file);

        if (out_buffer)
          cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,out_buffer_len+(out_buffer_ptr - out_buffer));
        else
          cookie_parse_buffer(tmpbuf,current_user,current_group,context,out_buffer_ptr,0);

        wzd_free(tmpbuf);

        cookie_ptr = out_buffer_ptr;
        cookie_length = strlen(cookie_ptr);
      }
    }
    break;
/*** SECTION cookies ***/
    case COOKIE_SECTIONNAME:
    {
      wzd_section_t * section;
      section = section_find(mainConfig->section_list,context->currentpath);
      snprintf(internalbuffer,IBUFSIZE,"%s",(section)?section_getname(section):"none");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
    }
      break;
/*** DISK/SPACE cookies ***/
    case COOKIE_SPACEFREE:
    {
      char dev_buffer[2048];
      long l_type, l_bsize, l_blocks, l_free;
      float f_blocks, f_free;
      char unit_blocks, unit_free;
      int ret;

      if (checkpath(".",dev_buffer,context)) {
        snprintf(internalbuffer,IBUFSIZE,"Could not get current path");
      } else {
        ret = get_device_info(dev_buffer,&l_type, &l_bsize, &l_blocks, &l_free);
        f_blocks = l_blocks*(float)l_bsize;
        f_free = l_free*(float)l_bsize;
        bytes_to_unit(&f_blocks,&unit_blocks);
        bytes_to_unit(&f_free,&unit_free);
        snprintf(internalbuffer,IBUFSIZE,"%.2f %c",f_free,unit_free);
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
    }
      break;
    case COOKIE_SPACETOTAL:
    {
      char dev_buffer[2048];
      long l_type, l_bsize, l_blocks, l_free;
      float f_blocks, f_free;
      char unit_blocks, unit_free;
      int ret;

      if (checkpath(".",dev_buffer,context)) {
        snprintf(internalbuffer,IBUFSIZE,"Could not get current path");
      } else {
        ret = get_device_info(dev_buffer,&l_type, &l_bsize, &l_blocks, &l_free);
        f_blocks = l_blocks*(float)l_bsize;
        f_free = l_free*(float)l_bsize;
        bytes_to_unit(&f_blocks,&unit_blocks);
        bytes_to_unit(&f_free,&unit_free);
        snprintf(internalbuffer,IBUFSIZE,"%.2f %c",f_blocks,unit_blocks);
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
    }
      break;
/*** USER cookies ***/
    case COOKIE_USERCREDITS2:
      convert = 1;
    case COOKIE_USERCREDITS:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        if (current_user->ratio)
        {
          total = current_user->credits;
          if (convert) {
#ifndef _MSC_VER
            val = (float)total;
#else
            val = (float)(__int64)total;
#endif
            bytes_to_unit(&val,&c);
            snprintf(internalbuffer,IBUFSIZE,"%.2f %c",val,c);
          } else
            snprintf(internalbuffer,IBUFSIZE,"%lld",total);
        } else
          snprintf(internalbuffer,IBUFSIZE,"unlimited");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usercredits");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
    case COOKIE_USERFILES_DL:
      get_cookie_format(yytext,&padding);
      if (current_user)
        snprintf(internalbuffer,IBUFSIZE,"%lu",current_user->stats.files_dl_total);
      else
        snprintf(internalbuffer,IBUFSIZE,"userfiles_dl");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERFILES_UL:
      get_cookie_format(yytext,&padding);
      if (current_user)
        snprintf(internalbuffer,IBUFSIZE,"%lu",current_user->stats.files_ul_total);
      else
        snprintf(internalbuffer,IBUFSIZE,"userfiles_ul");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERFLAGS:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        if (current_user->flags && strlen(current_user->flags)>0)
          snprintf(internalbuffer,IBUFSIZE,"%s",current_user->flags);
        else
          snprintf(internalbuffer,IBUFSIZE,"no flags");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userflags");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERGROUP:
      get_cookie_format(yytext,&padding);
      {
        wzd_group_t * group;
        if (current_user && current_user->group_num>0)
        {
          group = GetGroupByID(current_user->groups[0]);
          if (group) {
            snprintf(internalbuffer,IBUFSIZE,"%s",group->groupname);
          }
          else {
            snprintf(internalbuffer,IBUFSIZE,"invalid group");
          }
        }
        else
        {
          snprintf(internalbuffer,IBUFSIZE,"nogroup");
        }
        cookie_ptr = internalbuffer;
        cookie_length = strlen(cookie_ptr);
      }
      break;
    case COOKIE_USERGROUPS:
      get_cookie_format(yytext,&padding);
      {
        wzd_group_t * group;
        length = IBUFSIZE;
        cookie_ptr = internalbuffer;
        i = 0;
        if (current_user && current_user->group_num > 0) {
          while (current_user && (unsigned int)i < current_user->group_num)
          {
            group = GetGroupByID(current_user->groups[i]);
            if (group) {
              snprintf(cookie_ptr,length,"%s ",group->groupname);
              length -= strlen(group->groupname) + 1;
              cookie_ptr += strlen(group->groupname) + 1;
            }
            i++;
          }
          internalbuffer[strlen(internalbuffer)-1] = '\0';
        }
        else
        {
          snprintf(internalbuffer,IBUFSIZE,"nogroup");
        }
        cookie_ptr = internalbuffer;
        cookie_length = strlen(cookie_ptr);
      }
      break;
    case COOKIE_USERHOME:
      get_cookie_format(yytext,&padding);
      if (current_user) {
        wzd_user_t * user = NULL;
        /* check FLAG_SEE_HOME for self */
        if (real_context) user = GetUserByID(real_context->userid);
        if ( (user && strcmp(current_user->username,user->username)==0 ) || /* self */
          (me && me->flags && strchr(me->flags,FLAG_SEE_HOME))) /* authorized */
          snprintf(internalbuffer,IBUFSIZE,"%s",current_user->rootpath);
        else /* not allowed to see */
          snprintf(internalbuffer,IBUFSIZE,"- some where -");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userhome");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERID:
      get_cookie_format(yytext,&padding);
      if (current_user)
        snprintf(internalbuffer,IBUFSIZE,"%u",current_user->uid);
      else
        snprintf(internalbuffer,IBUFSIZE,"userid");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERIP:
      get_cookie_format(yytext,&padding);
      if (current_context)
      {
        /* check FLAG_SEE_IP for self */
        if (me && me->flags && strchr(me->flags,FLAG_SEE_IP)) {
          inet_ntop(CURRENT_AF,current_context->hostip,internalbuffer,sizeof(internalbuffer));
        } else { /* not allowed to see */
          snprintf(internalbuffer,IBUFSIZE,"xxx.xxx.xxx.xxx");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userip");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERIP_ALLOW:
      get_cookie_format(yytext,&padding);
      {
        unsigned long index;
        char *ptr;
        char *numstart;
        /* we can suppress check here, flex has already done his work */
        numstart = yytext+strlen(yytext)-1;
        while ( isdigit(*(numstart-1)) ) numstart--;
        index = strtoul(numstart,&ptr,10);
        if (index<HARD_IP_PER_USER)
        {
          if (current_user)
            snprintf(internalbuffer,IBUFSIZE,"%s",current_user->ip_allowed[index]);
          else
            snprintf(internalbuffer,IBUFSIZE,"userip_allow");
        } else {
          snprintf(internalbuffer,IBUFSIZE,"invalid index");
        }
      }
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERLASTCMD:
      get_cookie_format(yytext,&padding);
      if (current_context)
      {
        snprintf(internalbuffer,IBUFSIZE,"%s",current_context->last_command);
        if (strncasecmp(internalbuffer,"site",4)==0)
        {
          strcpy(internalbuffer,"SITE command");
        }
        if (strncasecmp(internalbuffer,"pass",4)==0)
        {
          strcpy(internalbuffer,"PASS xxxxx");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userlastcmd");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERLAST_LOGIN:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        if (user->last_login) {
          struct tm *ntime;
          ntime=localtime(&user->last_login);
		  if (ntime)
			strftime(internalbuffer,IBUFSIZE,"%b %d %H:%M",ntime);
		  else
		    snprintf(internalbuffer,IBUFSIZE,"never");
        } else
          snprintf(internalbuffer,IBUFSIZE,"never");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userlast_login");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERLEECHSLOTS:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%hu",current_user->leech_slots);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userleechslots");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERMAXDL:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_user->max_dl_speed);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usermaxdl");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERMAXIDLE:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_user->max_idle_time);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usermaxidle");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERMAXUL:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%u",current_user->max_ul_speed);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usermaxul");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERNAME:
      get_cookie_format(yytext,&padding);
      if (current_user)
        snprintf(internalbuffer,IBUFSIZE,"%s",current_user->username);
      else
        snprintf(internalbuffer,IBUFSIZE,"username");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERNUM_LOGINS:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%d",current_user->num_logins);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usernum_logins");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERPATH:
      get_cookie_format(yytext,&padding);
      if (context) {
        char dev_buffer[WZD_MAX_PATH+1];
        wzd_user_t * user = NULL;

        if (real_context) user = GetUserByID(real_context->userid);
        /* check FLAG_SEE_HOME for self */
        if ( me && 
          ((user && strcmp(me->username,user->username)==0) ||
          (me->flags && strchr(me->flags,FLAG_SEE_HOME))) ) {
          if (checkpath(context->currentpath,dev_buffer,context)) {
            snprintf(internalbuffer,IBUFSIZE,"Could not get current path");
          } else {
            strncpy(internalbuffer,dev_buffer,IBUFSIZE);
          }
        } else {
          snprintf(internalbuffer,IBUFSIZE,"- some where -");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userpwd");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERPID:
      get_cookie_format(yytext,&padding);
      if (current_context)
      {
        /* check FLAG_SITEOP for self */
        if (me && me->flags && strchr(me->flags,FLAG_SITEOP))
          snprintf(internalbuffer,IBUFSIZE,"%lu",current_context->pid_child);
        else
          snprintf(internalbuffer,IBUFSIZE,"some id");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userpid");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERPWD:
      get_cookie_format(yytext,&padding);
      if (context) {
        snprintf(internalbuffer,IBUFSIZE,"%s",context->currentpath);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userpwd");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERRATIO:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        if (current_user->ratio)
          snprintf(internalbuffer,IBUFSIZE,"1:%u",current_user->ratio);
        else
          snprintf(internalbuffer,IBUFSIZE,"unlimited");
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userratio");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERSLOTS:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%hu",current_user->user_slots);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userslots");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
   case COOKIE_USERSPEED:
      get_cookie_format(yytext,&padding);
      if (current_context)
      {
        if (strncasecmp(current_context->last_command,"retr",4)==0)
          snprintf(internalbuffer,IBUFSIZE,"%.1f kB/s",current_context->current_dl_limiter.current_speed/1024.f);
        else {
          if ((strncasecmp(current_context->last_command,"stor",4)==0) ||
              (strncasecmp(current_context->last_command,"appe",4)==0))
          {
            snprintf(internalbuffer,IBUFSIZE,"%.1f kB/s",current_context->current_ul_limiter.current_speed/1024.f);
          }
          else
            internalbuffer[0]='\0';
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"userspeed");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
   case COOKIE_USERTAG:
      get_cookie_format(yytext,&padding);
      if (current_user) {
        if (current_user->flags && strchr(current_user->flags,FLAG_DELETED)) {
          snprintf(internalbuffer,IBUFSIZE,"**DELETED**");
        } else {
          if (strlen(current_user->tagline)>0)
            snprintf(internalbuffer,IBUFSIZE,"%s",current_user->tagline);
          else
            snprintf(internalbuffer,IBUFSIZE,"no tagline set");
        }
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usertag");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_USERTIME:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        snprintf(internalbuffer,IBUFSIZE,"%s",time_to_str(time(NULL) - current_context->login_time));
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usertime");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
   case COOKIE_USERTOTAL_DL2:
      convert = 1;
   case COOKIE_USERTOTAL_DL:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        total = current_user->stats.bytes_dl_total;
        if (convert) {
#ifndef _MSC_VER
          val = (float)total;
#else
          val = (float)(__int64)total;
#endif
          bytes_to_unit(&val,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c",val,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%lld",total);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usertotal_dl");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
   case COOKIE_USERTOTAL_UL2:
      convert = 1;
   case COOKIE_USERTOTAL_UL:
      get_cookie_format(yytext,&padding);
      if (current_user)
      {
        total = current_user->stats.bytes_ul_total;
        if (convert) {
#ifndef _MSC_VER
          val = (float)total;
#else
          val = (float)(__int64)total;
#endif
          bytes_to_unit(&val,&c);
          snprintf(internalbuffer,IBUFSIZE,"%.2f %c",val,c);
        } else
          snprintf(internalbuffer,IBUFSIZE,"%lld",total);
      }
      else
        snprintf(internalbuffer,IBUFSIZE,"usertotal_ul");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      convert=0;
      break;
     /* XXX This is a little dansgerous because we don't know if strings
     * will be ok when used (although as address of constant data it should
     * always be ok) but we like sport !
     */
   case COOKIE_NOCOL:
      if (use_colors) {
        cookie_ptr = "[0m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_BLACK:
      if (use_colors) {
        cookie_ptr = "[30m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_RED:
      if (use_colors) {
        cookie_ptr = "[31m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_GREEN:
      if (use_colors) {
        cookie_ptr = "[32m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_BROWN:
      if (use_colors) {
        cookie_ptr = "[33m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_BLUE:
      if (use_colors) {
        cookie_ptr = "[34m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_MAGENTA:
      if (use_colors) {
        cookie_ptr = "[35m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_CYAN:
      if (use_colors) {
        cookie_ptr = "[36m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_WHITE:
      if (use_colors) {
        cookie_ptr = "[37m";
        cookie_length = strlen(cookie_ptr);
      } else
        continue;
      break;
   case COOKIE_ENDFOR:
#ifdef WZD_DBG_COOKIES
      out_err(LEVEL_HIGH,"endfor outside a for loop");
#endif
      continue;
    case COOKIE_INVALID: /* e.g This can be an explicit %s */
      snprintf(internalbuffer,IBUFSIZE,"%%%s",yytext);
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_EOL:
      cookie_ptr = "\r\n";
      cookie_length = 2;
      strncpy(send_buffer+send_buffer_ptr,cookie_ptr,cookie_length);
      send_buffer_ptr += cookie_length;
      if (send_buffer_ptr >= MIN_SEND_BUFFERSIZE) {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"flushing buffer on [31mEOL[0m");
#endif
        /* flush buffer */
        if (out_buffer) {
          unsigned int l = send_buffer_ptr;
          if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
            out_err(LEVEL_HIGH,"buffer truncated !");
#endif
            l = out_buffer_len - 1;
          }
          memcpy(out_buffer_ptr,send_buffer,l);
          out_buffer_ptr[l] = '\0';
          out_buffer_ptr += l;
          out_buffer_len -= l;
        } else {
          send_buffer[send_buffer_ptr]='\0';
          if (real_context)
            send_message_raw(send_buffer,real_context);
        }
        send_buffer_ptr=0;
      }
      continue;
    case COOKIE_VFSVIRTUAL:
      get_cookie_format(yytext,&padding);
      if (current_vfs)
        snprintf(internalbuffer,IBUFSIZE,"%s",current_vfs->virtual_dir);
      else
        snprintf(internalbuffer,IBUFSIZE,"virtual_dir");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_VFSPHYSICAL:
      get_cookie_format(yytext,&padding);
      if (current_vfs)
        snprintf(internalbuffer,IBUFSIZE,"%s",current_vfs->physical_dir);
      else
        snprintf(internalbuffer,IBUFSIZE,"physical_dir");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    case COOKIE_VFSTARGET:
      get_cookie_format(yytext,&padding);
      if (current_vfs)
      {
        if (current_vfs->target)
          snprintf(internalbuffer,IBUFSIZE,"%s",current_vfs->target);
        else
          snprintf(internalbuffer,IBUFSIZE,"not restricted");
      }

      else
        snprintf(internalbuffer,IBUFSIZE,"target");
      cookie_ptr = internalbuffer;
      cookie_length = strlen(cookie_ptr);
      break;
    default:
      cookie_ptr = yytext;
      cookie_length = strlen(cookie_ptr);
      break;
    }
    if (cookie_ptr) {
      if (padding) {
        if (cookie_length < padding) {
          for (;cookie_length<padding;cookie_length++) {
            cookie_ptr[cookie_length] = ' '; /* FIXME padding char hardcoded */
          }
        }
        cookie_ptr[padding] = '\0';
        cookie_length = padding;
      }
      /*      printf("%s",cookie_ptr);
              fflush(stdout);*/
      /* bufferize and send only complete lines */
      if (send_buffer_ptr + cookie_length >= MAX_SEND_BUFFERSIZE) {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"flushing buffer on [31mBUFFER OVERFLOW[0m");
#endif
        /* flush buffer */
        if (out_buffer) {
          unsigned int l = send_buffer_ptr;
          if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
            out_err(LEVEL_HIGH,"buffer truncated !");
#endif
            l = out_buffer_len - 1;
          }
          memcpy(out_buffer_ptr,send_buffer,l);
          out_buffer_ptr[l] = '\0';
          out_buffer_ptr += l;
          out_buffer_len -= l;
        } else {
          send_buffer[send_buffer_ptr]='\0';
          if (real_context)
            send_message_raw(send_buffer,real_context);
        }
        send_buffer_ptr=0;
      }
      strncpy(send_buffer+send_buffer_ptr,cookie_ptr,cookie_length);
      send_buffer_ptr += cookie_length;
    }
  }
  if ( --cookie_include_stack_ptr < 0 )
    yyterminate();
  else
  {
    yy_delete_buffer( YY_CURRENT_BUFFER );
    yy_switch_to_buffer(include_stack[cookie_include_stack_ptr] );
  }

#ifdef WZD_DBG_COOKIES
  out_err(LEVEL_HIGH,"flushing buffer on [31mEOF[0m (%d)",send_buffer_ptr);
#endif
  /* flush buffer */
  if (send_buffer_ptr) {
    if (send_buffer_ptr>2) {
      if (send_buffer[send_buffer_ptr-2]!= '\r' || send_buffer[send_buffer_ptr-1]!='\n') {
        strncpy(send_buffer+send_buffer_ptr,"\r\n",strlen("\r\n"));
        send_buffer_ptr += strlen("\r\n");
      }
    }
    else {
      strncpy(send_buffer+send_buffer_ptr,"\r\n",strlen("\r\n"));
      send_buffer_ptr += strlen("\r\n");
    }
    send_buffer[send_buffer_ptr]='\0';
    if (out_buffer) {
      unsigned int l = send_buffer_ptr;
      if (l >= out_buffer_len) {
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"buffer truncated !");
#endif
        l = out_buffer_len - 1;
      }
      memcpy(out_buffer_ptr,send_buffer,l);
      out_buffer_ptr[l] = '\0';
      out_buffer_ptr += l;
      out_buffer_len -= l;
#ifdef WZD_DBG_COOKIES
        out_err(LEVEL_HIGH,"buffer length %d (%d)",strlen(out_buffer),out_buffer_len);
#endif
    } else {
      if (real_context)
        send_message_raw(send_buffer,real_context);
    }
    send_buffer_ptr=0;
  }

  return 0;
}

