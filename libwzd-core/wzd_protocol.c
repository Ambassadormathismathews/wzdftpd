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
#include <string.h>

#include "wzd_structs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */


/** \brief Convert a 4-character string to an integer */
#define STRTOINT(a,b,c,d) (((a)<<24) + ((b)<<16) + ((c)<<8) + (d))

/** \brief Fast token identification function.
 *
 * Converts the string into an integer and return the corresponding
 * identifier. Luckily, all FTP commands are no more than 4 characters.
 */
int identify_token(char *token)
{
  unsigned int length;
  if (!token || (length=strlen(token))==0)
    return TOK_UNKNOWN;
  ascii_lower(token,length);

  /* TODO order the following by probability order */
  if (length <= 4) {
    switch ( STRTOINT(token[0],token[1],token[2],token[3]) ) {
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
  if (strcmp("\xff\xf2",token)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4\xff\xf2",token)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4",token)==0) /* telnet IP */
    return TOK_NOTHING;
  if (strcmp("\xff",token)==0) /* telnet SYNCH */
    return TOK_NOTHING;
  return TOK_UNKNOWN;
}

