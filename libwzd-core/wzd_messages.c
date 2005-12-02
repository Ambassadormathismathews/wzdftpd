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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#if defined(WIN32)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h> /* O_RDONLY */

#include "wzd_structs.h"
#include "wzd_misc.h"
#include "wzd_log.h"

#include "wzd_cache.h"
#include "wzd_section.h"
#include "wzd_utf8.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

#define DEFAULT_MSG	"No message for this code"

#define BUFFER_LEN	4096

char *msg_tab[HARD_MSG_LIMIT];

void init_default_messages(void)
{
  memset(msg_tab,0,HARD_MSG_LIMIT*sizeof(char *));

  msg_tab[150] = strdup("Status OK, about to open data connection.");

  msg_tab[200] = strdup("%s"); /* Command okay */
  msg_tab[202] = strdup("Command not implemented.");
  msg_tab[211] = strdup("%s");
  msg_tab[213] = strdup("%s"); /* mdtm */
  msg_tab[214] = strdup("The following commands can be used:\n"
      "SITE TYPE PORT PASV EPRT EPSV ABOR PWD ALLO FEAT NOOP\n"
      "SYST RNFR RNTO CWD LIST STAT MKD  RMD RETR STOR REST\n"
      "MDTM SIZE DELE PRET XCRC XMD5 OPTS HELP QUIT\n"
      "Help OK"); /* TODO sort */
  msg_tab[215] = strdup("UNIX Type: L8");
  msg_tab[220] = strdup("wzd server ready.");
  msg_tab[221] = strdup("Cya !");
  msg_tab[226] = strdup("Closing data connection.\r\n%msg\r\n- [Section: %sectionname] - [Free: %spacefree] - [Dl: %usertotal_dl2] - [Ul: %usertotal_ul2] -");
  msg_tab[227] = strdup("Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hu,%hu)"); /* DON'T TOUCH ! */
  msg_tab[230] = strdup("User logged in, proceed.");
  msg_tab[234] = strdup("AUTH command OK. Initializing %s mode"); /* SSL init */
  msg_tab[235] = strdup("%s%s");
  msg_tab[250] = strdup("%s%s");
/*  msg_tab[257] = strdup("\"%s\" %s");*/
  msg_tab[258] = strdup("\"%s\" %s");

  msg_tab[331] = strdup("User %s okay, need password.");
  msg_tab[334] = strdup("%s%s");
  msg_tab[350] = strdup("%s"); /* "Restarting at %ld. Send STORE or RETRIEVE.", or "OK, send RNTO" */

  msg_tab[421] = strdup("%s"); /* Service not available, closing control connection. */
  msg_tab[425] = strdup("Can't open data connection.");
  msg_tab[426] = strdup("Error occured, data connection closed.");
  msg_tab[431] = strdup("%s"); /* Unable to accept security mechanism. */
  msg_tab[451] = strdup("Transmission error occured.");
  msg_tab[491] = strdup("Data connection already active.");

  msg_tab[501] = strdup("%s");
  msg_tab[502] = strdup("Command not implemented.");
  msg_tab[503] = strdup("%s");
  msg_tab[530] = strdup("%s"); /* Not logged in." */
  msg_tab[535] = strdup("%s"); /* Not logged in." */
  msg_tab[550] = strdup("%s: %s");
  msg_tab[553] = strdup("Requested action not taken: %s");
}

void free_messages(void)
{
  int i;

  for (i=0; i<HARD_MSG_LIMIT; i++)
  {
    if (msg_tab[i]) {
      free(msg_tab[i]);
      msg_tab[i]=0;
    }
  }
}

const char * getMessage(int code, int *must_free)
{
  const char * ptr;
  char * file_buffer;
  unsigned long filesize, size;
  u64_t sz64;

  if (code < 0 || code > HARD_MSG_LIMIT)
    return DEFAULT_MSG;
  *must_free = 0;
  ptr = msg_tab[code];
  if (!ptr || strlen(ptr)==0) return DEFAULT_MSG;
  if (ptr[0]=='+') { /* returns file content */
    wzd_cache_t * fp;
    fp = wzd_cache_open(ptr+1,O_RDONLY,0644);
    if (!fp) return DEFAULT_MSG;
    sz64 = wzd_cache_getsize(fp);
	if (sz64 > INT_MAX) {
      out_log(LEVEL_HIGH,"%s:%d couldn't allocate " PRIu64 " bytes for message %d\n",__FILE__,__LINE__,code);
	  wzd_cache_close(fp);
	  *must_free = 0;
	  return NULL;
	}
	filesize = (unsigned int) sz64;
    file_buffer = wzd_malloc(filesize+1);
    if ( (size=wzd_cache_read(fp,file_buffer,filesize))!=filesize ) {
      wzd_free(file_buffer);
      wzd_cache_close(fp);
      return DEFAULT_MSG;
    }
    file_buffer[filesize]='\0';
    wzd_cache_close(fp);
    *must_free = 1;
    return file_buffer;
  }
  return ptr;
}

void setMessage(const char *newMessage, int code)
{
  if (code < 0 || code > HARD_MSG_LIMIT) return;
  if (msg_tab[code]) free(msg_tab[code]);
  msg_tab[code] = (char*)newMessage;
}

/*************** send_message ************************/

int send_message(int code, wzd_context_t * context)
{
  wzd_string_t * str;
  int ret;

  str = format_message(context,code);
#ifdef DEBUG
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s",(unsigned long)context->pid_child,str_tochar(str));
#endif
  ret = (context->write_fct)(context->controlfd,str_tochar(str),str_length(str),0,HARD_XFER_TIMEOUT,context);

  str_deallocate(str);

  return ret;
}

/*************** send_message_with_args **************/

int send_message_with_args(int code, wzd_context_t * context, ...)
{
  va_list argptr;
  wzd_string_t * str;
  int ret;

  va_start(argptr,context); /* note: ansi compatible version of va_start */
  str = v_format_message(context,code,argptr);
#ifdef HAVE_UTF8
  if (context->connection_flags & CONNECTION_UTF8)
  {
    if (!str_is_valid_utf8(str))
      str_local_to_utf8(str,local_charset());
  }
#endif
  va_end (argptr);
#ifdef DEBUG
  out_err(LEVEL_FLOOD,"<thread %ld> ->ML %s",(unsigned long)context->pid_child,str_tochar(str));
#endif
  ret = (context->write_fct)(context->controlfd,str_tochar(str),strlen(str_tochar(str)),0,HARD_XFER_TIMEOUT,context);

  str_deallocate(str);
  return 0;
}

/*************** send_message_raw ********************/

int send_message_raw(const char *msg, wzd_context_t * context)
{
  int ret;

  if (!msg || strlen(msg)==0) return 0;

#ifdef DEBUG
if (msg[strlen(msg)-1]!='\n')
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s\n",(unsigned long)context->pid_child,msg);
else
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s",(unsigned long)context->pid_child,msg);
#endif
  ret = (context->write_fct)(context->controlfd,msg,strlen(msg),0,HARD_XFER_TIMEOUT,context);

  return ret;
}
