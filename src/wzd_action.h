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

typedef enum {
  TOK_UNKNOWN=0,
  TOK_HELP,
  TOK_USER,
  TOK_PASS,
  TOK_AUTH,
  TOK_QUIT,
  TOK_TYPE,
  TOK_MODE,
  TOK_PORT,
  TOK_PASV,
  TOK_PWD,
  TOK_NOOP,
  TOK_SYST,
  TOK_CWD,
  TOK_CDUP,
  TOK_LIST,
  TOK_NLST,
  TOK_STAT,
  TOK_MKD,
  TOK_RMD,
  TOK_RETR,
  TOK_STOR,
  TOK_REST,
  TOK_MDTM,
  TOK_SIZE,
  TOK_DELE,
  TOK_ABOR,

  TOK_PBSZ,
  TOK_PROT,
  TOK_CPSV,
  TOK_SSCN,

  TOK_SITE,
  TOK_FEAT,
  TOK_ALLO,
  TOK_RNFR,
  TOK_RNTO,
  TOK_APPE,

  TOK_EPSV,
  TOK_EPRT,
  TOK_PRET,

  TOK_XCRC,
  TOK_XMD5,

  TOK_OPTS,

  TOK_MLST,
  TOK_MLSD,

  TOK_SITE_ADDIP=64,
  TOK_SITE_ADDUSER,
  TOK_SITE_BACKEND,
  TOK_SITE_CHACL,
  TOK_SITE_CHANGE,
  TOK_SITE_CHANGEGRP,
  TOK_SITE_CHECKPERM,
  TOK_SITE_CHGRP,
  TOK_SITE_CHMOD,
  TOK_SITE_CHOWN,
  TOK_SITE_CHPASS,
  TOK_SITE_CHRATIO,
  TOK_SITE_CLOSE,
  TOK_SITE_COLOR,
  TOK_SITE_DELIP,
  TOK_SITE_DELUSER,
  TOK_SITE_FLAGS,
  TOK_SITE_FREE,
  TOK_SITE_GINFO,
  TOK_SITE_GIVE,
  TOK_SITE_GROUP,
  TOK_SITE_GROUPS,
  TOK_SITE_GRPADD,
  TOK_SITE_GRPADDIP,
  TOK_SITE_GRPCHANGE,
  TOK_SITE_GRPDEL,
  TOK_SITE_GRPDELIP,
  TOK_SITE_GRPKILL,
  TOK_SITE_GRPRATIO,
  TOK_SITE_GRPREN,
  TOK_SITE_GSINFO,
  TOK_SITE_HELP,
  TOK_SITE_IDLE,
  TOK_SITE_INVITE,
  TOK_SITE_KICK,
  TOK_SITE_KILL,
  TOK_SITE_KILLPATH,
  TOK_SITE_LINK,
  TOK_SITE_MSG,
  TOK_SITE_PERM,
  TOK_SITE_PURGE,
  TOK_SITE_READD,
  TOK_SITE_RELOAD,
  TOK_SITE_REOPEN,
  TOK_SITE_RULES,
  TOK_SITE_RUSAGE,
  TOK_SITE_SAVECFG,
  TOK_SITE_SHUTDOWN,
  TOK_SITE_SWHO,
  TOK_SITE_SU,
  TOK_SITE_TAGLINE,
  TOK_SITE_TAKE,
  TOK_SITE_TEST,
  TOK_SITE_UNLOCK,
  TOK_SITE_UPTIME,
  TOK_SITE_USER,
  TOK_SITE_USERS,
  TOK_SITE_UTIME,
  TOK_SITE_VARS,
  TOK_SITE_VARS_GROUP,
  TOK_SITE_VARS_USER,
  TOK_SITE_VERSION,
  TOK_SITE_VFSLS,
  TOK_SITE_VFSADD,
  TOK_SITE_VFSDEL,
  TOK_SITE_WHO,
  TOK_SITE_WIPE,

  TOK_NOTHING=256,
} wzd_token_t;


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

  fd_t		current_file;
  u64_t	bytesnow;

  time_t	tm_start;
  struct timeval tv_start;
} wzd_action_t;

#endif /* __WZD_ACTION__ */

