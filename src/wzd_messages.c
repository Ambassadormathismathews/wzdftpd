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

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
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

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"
#include "wzd_misc.h"
#include "wzd_log.h"

#include "wzd_cache.h"
#include "wzd_section.h"
#include "wzd_vfs.h"


#define DEFAULT_MSG	"No message for this code"

#define BUFFER_LEN	4096

char *msg_tab[HARD_MSG_LIMIT];

void init_default_messages(void)
{
  memset(msg_tab,0,HARD_MSG_LIMIT*sizeof(char *));

  msg_tab[150] = strdup("Status OK, about to open data connection.");

  msg_tab[200] = strdup("%s"); /* Command okay */
  msg_tab[202] = strdup("Command not implemented.");
  msg_tab[211] = strdup("Extension supported\n%s");
  msg_tab[213] = strdup("%s"); /* mdtm */
  msg_tab[215] = strdup("UNIX Type: L8");
  msg_tab[220] = strdup("wzd server ready.");
  msg_tab[221] = strdup("Cya !");
  msg_tab[226] = strdup("Closing data connection.");
  msg_tab[227] = strdup("Entering Passive Mode (%d,%d,%d,%d,%d,%d)"); /* DON'T TOUCH ! */
  msg_tab[230] = strdup("User logged in, proceed.");
  msg_tab[234] = strdup("AUTH command OK. Initializing %s mode"); /* SSL init */
  msg_tab[250] = strdup("%s%s");
  msg_tab[257] = strdup("\"%s\" %s");
  msg_tab[258] = strdup("%s %s");

  msg_tab[331] = strdup("User %s okay, need password.");
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

  if (code < 0 || code > HARD_MSG_LIMIT)
    return DEFAULT_MSG;
  *must_free = 0;
  ptr = msg_tab[code];
  if (!ptr || strlen(ptr)==0) return DEFAULT_MSG;
  if (ptr[0]=='+') { /* returns file content */
    wzd_cache_t * fp;
    fp = wzd_cache_open(ptr+1,O_RDONLY,0644);
    if (!fp) return DEFAULT_MSG;
    filesize = wzd_cache_getsize(fp);
    file_buffer = malloc(filesize+1);
    if ( (size=wzd_cache_read(fp,file_buffer,filesize))!=filesize ) {
      free(file_buffer);
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
  char buffer[BUFFER_LEN];
  int ret;

  format_message(code,BUFFER_LEN,buffer);
#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s\n",(unsigned long)context->pid_child,buffer);
else
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s",(unsigned long)context->pid_child,buffer);
#endif
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);
/*  sprintf(buffer,"%3d \r\n",code);
  ret = (context->write_fct)(context->controlfd,buffer,6,0,HARD_XFER_TIMEOUT,context);*/

  return ret;
}

/*************** send_message_with_args **************/

int send_message_with_args(int code, wzd_context_t * context, ...)
{
  va_list argptr;
  char buffer[BUFFER_LEN];
  int ret;

  va_start(argptr,context); /* note: ansi compatible version of va_start */
  v_format_message(code,BUFFER_LEN,buffer,argptr);
#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s\n",(unsigned long)context->pid_child,buffer);
else
  out_err(LEVEL_FLOOD,"<thread %ld> -> %s",(unsigned long)context->pid_child,buffer);
#endif
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

  return 0;
}

/*************** send_message_raw ********************/

int send_message_raw(const char *msg, wzd_context_t * context)
{
  int ret;

/*#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"I answer: %s\n",buffer);
else
  out_err(LEVEL_FLOOD,"I answer: %s",buffer);
#endif*/
  ret = (context->write_fct)(context->controlfd,msg,strlen(msg),0,HARD_XFER_TIMEOUT,context);

  return ret;
}

/*************** write_message_footer ****************/

int write_message_footer(int code, wzd_context_t * context)
{
  char buffer[2048];
  char buf_section[256];
  int ret;
  long f_type, f_bsize, f_blocks, f_free;
  float free,total;
  float bytes_ul, bytes_dl, bytes_credits;
  char unit, unit_dl, unit_ul, unit_credits;
  wzd_user_t * user;
  wzd_section_t * section;

  if (checkpath(".",buffer,context)) {
    send_message_with_args(501,context,". does not exist ?!");
    return -1;
  }

  user = GetUserByID(context->userid);

  ret = get_device_info(buffer,&f_type, &f_bsize, &f_blocks, &f_free);

  unit='k';
  free = f_free*(f_bsize/1024.f);
  total = f_blocks*(f_bsize/1024.f);

  if (total > 1000.f) {
    unit='M';
    free /= 1024.f;
    total /= 1024.f;
  }
  if (total > 1000.f) {
    unit='G';
    free /= 1024.f;
    total /= 1024.f;
  }

#ifndef _MSC_VER
  bytes_dl = (float)user->stats.bytes_dl_total;
  bytes_ul = (float)user->stats.bytes_ul_total;
#else
  bytes_dl = (float)(__int64)user->stats.bytes_dl_total;
  bytes_ul = (float)(__int64)user->stats.bytes_ul_total;
#endif

  bytes_to_unit(&bytes_dl,&unit_dl);
  bytes_to_unit(&bytes_ul,&unit_ul);

  section = section_find(mainConfig->section_list,context->currentpath);
  if (section) {
    snprintf(buf_section,255,"[Section: %s] - ",section_getname(section));
  } else {
    buf_section[0] = '\0';
  }

  if (user->ratio) {
#ifndef _MSC_VER
    bytes_credits = (float)user->credits;
#else
    bytes_credits = (float)(__int64)user->credits;
#endif
    bytes_to_unit(&bytes_credits,&unit_credits);
    snprintf(buffer,2047,"%3d - %s[Free: %.2f %c] - [Dl: %.2f %c] - [Ul: %.2f %c] - [Cred: %.2f %c] -\r\n",
      code,buf_section,free,unit,bytes_dl,unit_dl,bytes_ul,unit_ul,
      bytes_credits,unit_credits);
  } else {
    snprintf(buffer,2047,"%3d - %s[Free: %.2f %c] - [Dl: %.2f %c] - [Ul: %.2f %c] -\r\n",
      code,buf_section,free,unit,bytes_dl,unit_dl,bytes_ul,unit_ul);
  }
  ret = send_message_raw(buffer, context);

  return 0;
}
