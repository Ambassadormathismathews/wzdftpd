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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wzd_structs.h"

#include "wzd_commands.h"
#include "wzd_log.h"
#include "wzd_misc.h" /* ascii_lower */
#include "wzd_protocol.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */


static int _basic_check_ftp(const char * command);

/** \brief Convert a 4-character string to an integer */
#define STRTOINT(a,b,c,d) (((a)<<24) + ((b)<<16) + ((c)<<8) + (d))


/** \brief Allocate memory for a ftp_command_t structure */
struct ftp_command_t * alloc_ftp_command(void)
{
  struct ftp_command_t * command;

  command = wzd_malloc(sizeof(struct ftp_command_t));
  memset(command,0,sizeof(struct ftp_command_t));

  return command;
}

/** \brief Free memory used by a \a ftp_command_t structure */
void free_ftp_command(struct ftp_command_t * command)
{
  if (command == NULL) return;

  str_deallocate(command->command_name);
  str_deallocate(command->args);

  wzd_free(command);
}


/** \brief Fast token identification function.
 *
 * Converts the string into an integer and return the corresponding
 * identifier. Luckily, all FTP commands are no more than 4 characters.
 */
int identify_token(const char *token)
{
  unsigned int length;
  char buf[4];
  if (!token || (length=strlen(token))==0)
    return TOK_UNKNOWN;
  memcpy(buf,token,4);
  ascii_lower(buf,length);

  /* TODO order the following by probability order */
  if (length <= 4) {
    switch ( STRTOINT(buf[0],buf[1],buf[2],buf[3]) ) {
      case STRTOINT('h','e','l','p'): return TOK_HELP;
      case STRTOINT('u','s','e','r'): return TOK_USER;
      case STRTOINT('p','a','s','s'): return TOK_PASS;
      case STRTOINT('a','u','t','h'): return TOK_AUTH;
      case STRTOINT('q','u','i','t'): return TOK_QUIT;
      case STRTOINT('t','y','p','e'): return TOK_TYPE;
      case STRTOINT('m','o','d','e'): return TOK_MODE;
      case STRTOINT('p','o','r','t'): return TOK_PORT;
      case STRTOINT('p','a','s','v'): return TOK_PASV;
      case STRTOINT('p','w','d','\0'): return TOK_PWD;
      case STRTOINT('n','o','o','p'): return TOK_NOOP;
      case STRTOINT('s','y','s','t'): return TOK_SYST;
      case STRTOINT('c','w','d','\0'): return TOK_CWD;
      case STRTOINT('c','d','u','p'): return TOK_CDUP;
      case STRTOINT('l','i','s','t'): return TOK_LIST;
      case STRTOINT('n','l','s','t'): return TOK_NLST;
      case STRTOINT('m','l','s','t'): return TOK_MLST;
      case STRTOINT('m','l','s','d'): return TOK_MLSD;
      case STRTOINT('m','k','d','\0'): return TOK_MKD;
      case STRTOINT('r','m','d','\0'): return TOK_RMD;
      case STRTOINT('r','e','t','r'): return TOK_RETR;
      case STRTOINT('s','t','o','r'): return TOK_STOR;
      case STRTOINT('a','p','p','e'): return TOK_APPE;
      case STRTOINT('r','e','s','t'): return TOK_REST;
      case STRTOINT('m','d','t','m'): return TOK_MDTM;
      case STRTOINT('s','i','z','e'): return TOK_SIZE;
      case STRTOINT('d','e','l','e'): return TOK_DELE;
      case STRTOINT('a','b','o','r'): return TOK_ABOR;
      case STRTOINT('p','b','s','z'): return TOK_PBSZ;
      case STRTOINT('p','r','o','t'): return TOK_PROT;
      case STRTOINT('c','p','s','v'): return TOK_CPSV;
      case STRTOINT('s','s','c','n'): return TOK_SSCN;
      case STRTOINT('s','i','t','e'): return TOK_SITE;
      case STRTOINT('f','e','a','t'): return TOK_FEAT;
      case STRTOINT('a','l','l','o'): return TOK_ALLO;
      case STRTOINT('r','n','f','r'): return TOK_RNFR;
      case STRTOINT('r','n','t','o'): return TOK_RNTO;
      case STRTOINT('i','d','n','t'): return TOK_IDNT;
      /* IPv6 */
      case STRTOINT('e','p','s','v'): return TOK_EPSV;
      case STRTOINT('e','p','r','t'): return TOK_EPRT;
      /* extensions */
      case STRTOINT('p','r','e','t'): return TOK_PRET;
      case STRTOINT('x','c','r','c'): return TOK_XCRC;
      case STRTOINT('x','m','d','5'): return TOK_XMD5;
      case STRTOINT('o','p','t','s'): return TOK_OPTS;
      case STRTOINT('m','o','d','a'): return TOK_MODA;
      case STRTOINT('a','d','a','t'): return TOK_ADAT;
      case STRTOINT('m','i','c','\0'): return TOK_MIC;
/*      default:
        return TOK_UNKNOWN;*/
    }
  }

  /* XXX FIXME TODO the following sequence can be divided into parts, and MUST be followed by either
   * STAT or ABOR or QUIT
   * we should return TOK_PREPARE_SPECIAL_CMD or smthing like this
   * and wait the next command
   */
  if (strcmp("\xff\xf2",buf)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4\xff\xf2",buf)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4",buf)==0) /* telnet IP */
    return TOK_NOTHING;
  if (strcmp("\xff",buf)==0) /* telnet SYNCH */
    return TOK_NOTHING;
  return TOK_UNKNOWN;
}

/** \brief Parse and identify FTP command
 *
 * \note Input string is modified.
 */
struct ftp_command_t * parse_ftp_command(wzd_string_t * s)
{
  struct ftp_command_t * ftp_command = NULL;
  wzd_string_t * token;
  wzd_command_t * command;

out_log(LEVEL_FLOOD,"DEBUG parse_ftp_command(\"%s\")\n",str_tochar(s));

  if (_basic_check_ftp(str_tochar(s)) != 0) {
    out_log(LEVEL_NORMAL,"FTP Error while decoding \"%s\"\n",str_tochar(s));
    return NULL;
  }

  token = str_tok(s," ");
  if (token == NULL) {
    out_log(LEVEL_NORMAL,"FTP Error empty command received, ignoring\n");
    return NULL;
  }

  command = commands_find(mainConfig->commands_list,token);

  if (command == NULL) {
    if (str_length(s) > 0)
      out_log(LEVEL_NORMAL,"WARNING unknown command received \"%s %s\"\n",str_tochar(token),str_tochar(s));
    else
      out_log(LEVEL_NORMAL,"WARNING unknown command received \"%s\"\n",str_tochar(token));
    str_deallocate(token);
    return NULL;
  }

  if (command->id == TOK_SITE) {
    wzd_string_t * site_command;
    wzd_command_t * command_real;

    site_command = str_tok(s," \t");
    if (site_command == NULL) {
      /** \todo command is "site" without arguments. Return site help ? */
      out_log(LEVEL_NORMAL,"WARNING received site command without arguments\n");
      str_deallocate(token);
      return NULL;
    }
    str_append(str_append(token,"_"),str_tochar(site_command));
    str_tolower(token);
    command_real = commands_find(mainConfig->commands_list,token);
    if (command_real) command = command_real;
    str_deallocate(site_command);
  }

  if (command == NULL) {
    if (str_length(s) > 0)
      out_log(LEVEL_NORMAL,"WARNING could not parse command \"%s %s\"\n",str_tochar(token),str_tochar(s));
    else
      out_log(LEVEL_NORMAL,"WARNING could not parse command \"%s\"\n",str_tochar(token));
    str_deallocate(token);
    return NULL;
  }

  ftp_command = alloc_ftp_command();

  ftp_command->command_name = token;
  ftp_command->args = s;
  ftp_command->command = command;

  return ftp_command;
}

/** \brief Run basic tests on RFC compliance on input string
 *
 * \return 0 if ok
 */
static int _basic_check_ftp(const char * command)
{
  const char *p = command;

  if (command == NULL) return -1;

  /* find first space position */
  while (*p && *p != ' ')
    p++;

  if ( (p - command) > 4 ) {
    out_log(LEVEL_INFO,"FTP warning: first token is more than 4 characters\n");
    return 1;
  }

  if (*p == '\0') /* only one token */
    return 0;

  if (*(p+1) == ' ') {
    out_log(LEVEL_INFO,"FTP Warning: only one space allowed after first token\n");
    return 1;
  }

  return 0;
}
