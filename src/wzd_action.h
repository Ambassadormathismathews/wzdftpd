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

#ifndef __WZD_ACTION__
#define __WZD_ACTION__

#define TOK_UNKNOWN     0
#define TOK_USER        1
#define TOK_PASS        2
#define TOK_AUTH        3
#define TOK_QUIT        4
#define TOK_TYPE        5
#define TOK_MODE        6
#define TOK_PORT        7
#define TOK_PASV        8
#define TOK_PWD         9
#define TOK_NOOP        10
#define TOK_SYST        11
#define TOK_CWD         12
#define TOK_CDUP        13
#define TOK_LIST        14
#define TOK_NLST        15
#define TOK_STAT        16
#define TOK_MKD         17
#define TOK_RMD         18
#define TOK_RETR        19
#define TOK_STOR        20
#define TOK_REST        21
#define TOK_MDTM        22
#define TOK_SIZE        23
#define TOK_DELE        24
#define TOK_ABOR        25

#define TOK_PBSZ        26
#define TOK_PROT        27

#define TOK_SITE        28
#define TOK_FEAT        29
#define	TOK_ALLO	30
#define	TOK_RNFR	31
#define	TOK_RNTO	32
#define	TOK_APPE	33

#define	TOK_EPSV	34
#define	TOK_EPRT	35
#define TOK_PRET        36

#define TOK_XCRC        37
#define TOK_XMD5        38

#define TOK_OPTS        39

#define	TOK_NOTHING	64

struct last_file_t {
    char	name[WZD_MAX_PATH];
    time_t	time;
    struct timeval tv;
    u64_t	size;
    unsigned int token;
};

typedef struct {
  unsigned int	token;
  char		arg[HARD_LAST_COMMAND_LENGTH];

/*  FILE *	current_file;*/
  int		current_file;
  u64_t	bytesnow;

  time_t	tm_start;
  struct timeval tv_start;
} wzd_action_t;

#endif /* __WZD_ACTION__ */

