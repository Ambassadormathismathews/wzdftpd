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

/* Sanity check */
#ifdef WZD_MULTIPROCESS
#ifdef WZD_MULTITHREAD

#error "You CAN'T have a multi-thread multi-process server, stupid !"

#endif /* WZD_MULTITHREAD */
#endif /* WZD_MULTIPROCESS */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <regex.h>
#include <errno.h>
#include <fcntl.h>

#include <syslog.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_misc.h"
#include "wzd_log.h"
#include "wzd_tls.h"
#include "wzd_init.h"
#include "wzd_libmain.h"
#include "wzd_ServerThread.h"
#include "wzd_opts.h"

#include "wzd_debug.h"

char configfile_name[256];
int stay_foreground=0;

extern short created_shm;

void display_usage(void)
{
  fprintf(stderr,"%s build %lu (%s)\n",
         WZD_VERSION_STR,(unsigned long)WZD_BUILD_NUM,WZD_BUILD_OPTS);
  fprintf(stderr, "\nusage: wzdftpd [arguments]\n");
  fprintf(stderr,"\narguments:\r\n");
#ifdef HAVE_GETOPT
  fprintf(stderr," -h, --help                  - Display this text \n");
#if DEBUG
  fprintf(stderr," -b, --background            - Force background \n");
#endif
  fprintf(stderr," -d,                         - Delete IPC if present (Linux only) \n");
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s, --force-foreground      - Stay in foreground \n");
  fprintf(stderr," -V, --version               - Show version \n");
#else /* HAVE_GETOPT */
  fprintf(stderr," -h                          - Display this text \n");
#if DEBUG
  fprintf(stderr," -b                          - Force background \n");
#endif
  fprintf(stderr," -d,                         - Delete IPC if present (Linux only) \n");
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s                          - Stay in foreground \n");
  fprintf(stderr," -V                          - Show version \n");

#endif /* HAVE_GETOPT */
}

void cleanup_shm(void)
{
  char buffer[1024];
  char value[1024];
  char varname[1024];
  char *ptr;
  regex_t reg_line;
  regmatch_t regmatch[3];
  FILE *configfile;
  int length, err;
  unsigned long shm_key=0x1331c0d3;

  configfile = fopen(configfile_name,"r");
  if (!configfile)
    return;

  while (fgets(buffer,1024,configfile))
  {
    ptr = buffer;
    length = strlen(buffer); /* fgets put a '\0' at the end */
    /* trim leading spaces */
    while (((*ptr)==' ' || (*ptr)=='\t') && (length-- > 0))
      ptr++;
    if ((*ptr)=='#' || length<=1)       /* comment and empty lines */
      continue;

    /* TODO if line contains a " and is not ended, it is a multi-line */
    /* TODO replace special chars (\n,\t,\xxx,etc) */

    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    if (length <= 0) continue;

    reg_line.re_nsub = 2;
    err = regcomp (&reg_line, "^([-]?[a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
    if (err) {
      out_log(LEVEL_CRITICAL,"Regexp could not compile (file %s line %d)\n",__FILE__,__LINE__);
      out_log(LEVEL_CRITICAL,"Possible error cause: bad libc installation\n");
      exit (1);
    }

    err = regexec(&reg_line,ptr,3,regmatch,0);
    if (err) {
      out_log(LEVEL_HIGH,"Line '%s' does not respect config line format - ignoring\n",buffer);
    } else {
      memcpy(varname,ptr+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
      varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
      memcpy(value,ptr+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
      value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

      if (strcasecmp(varname,"shm_key")==0) {
	unsigned long new_key=0;
	errno = 0;
	new_key = strtoul(value,(char**)NULL,0);
	if (errno == ERANGE) return;
	shm_key = new_key;
      }
    }
  }
  fclose(configfile);

  wzd_shm_cleanup(shm_key-1);
  wzd_shm_cleanup(shm_key);
}


int main_parse_args(int argc, char **argv)
{
  int opt;


#ifdef HAVE_GETOPT
  static struct option long_options[] =
  {
    /* Options without arguments: */
    { "background", no_argument, NULL, 'b' },
    { "config-file", required_argument, NULL, 'f' },
    { "help", no_argument, NULL, 'h' },
    { "force-foreground", no_argument, NULL, 's' },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 } /* sentinel */
  };

  /* please keep options ordered ! */
/*  while ((opt=getopt(argc, argv, "hbdf:sV")) != -1) {*/
  while ((opt=getopt_long(argc, argv, "hbdf:sV", long_options, (int *)0)) != -1)
#else /* HAVE_GETOPT */
  while ((opt=getopt(argc, argv, "hbdf:sV")) != -1)
#endif /* HAVE_GETOPT */
  {
    switch((char)opt) {
    case 'b':
      stay_foreground = 0;
      break;
    case 'd':
/*      readConfigFile("wzd.cfg");*/
      cleanup_shm();
      return 1;
    case 'f':
      if (strlen(optarg)>=255) {
	fprintf(stderr,"filename too long (>255 chars)\n");
	return 1;
      }
      strncpy(configfile_name,optarg,255);
      break;
    case 'h':
      display_usage();
      return 1;
    case 's':
      stay_foreground = 1;
      break;
    case 'V':
      fprintf(stderr,"%s build %lu (%s)\n",
	  WZD_VERSION_STR,(unsigned long)WZD_BUILD_NUM,WZD_BUILD_OPTS);
      return 1;
    }
  }

  return 0;
}



int main(int argc, char **argv)
{
  int fd;
  int ret;
  int forkresult;
  wzd_config_t * config;
  struct stat s;

#if 0
  fprintf(stderr,"--------------------------------------\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"This is a beta release, in active development\n");
  fprintf(stderr,"Things may break from version to version\n");
  fprintf(stderr,"Want stability ? Use a 0.1rc4 version. YOU WERE WARNED!\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"--------------------------------------\n");
  fprintf(stderr,"\n");
#endif

#if DEBUG
  stay_foreground = 1;
#endif
  /* default value */
  strcpy(configfile_name,"wzd.cfg");

  if (argc > 1) {
    ret = main_parse_args(argc,argv);
    if (ret) {
      return 0;
    }
  }

  if (!stay_foreground) {
    forkresult = fork();

    if ((int)forkresult == -1)
      out_err(LEVEL_CRITICAL,"Could not fork into background\n");
    if ((int)forkresult != 0)
      exit(0);
  }

  /* initialize random seed */
  srand((int)(time(NULL)+0x13313043));

  /* not really usefull, but will also initialize var if not used :) */
#ifndef __CYGWIN__
  wzd_server_uid = geteuid();
#endif

  /* find config file */
  if (stat(configfile_name,&s)) {
    strcpy(configfile_name,"/etc/wzd.cfg");
    if (stat(configfile_name,&s)) {
      strcpy(configfile_name,"/etc/wzdftpd/wzd.cfg");
      if (stat(configfile_name,&s)) {
	out_err(LEVEL_CRITICAL,"Could not find config file\n");
	exit(1);
      }
    }
  }

  config = NULL;
  config = readConfigFile(configfile_name);
  
  if (!config) {
    out_err(LEVEL_CRITICAL,"Critical error loading config file, aborting\n");
    exit(1);
  }

  mainConfig_shm = wzd_shm_create(config->shm_key-1,sizeof(wzd_config_t),0);
  if (mainConfig_shm == NULL) {
    /* 2nd chance ? */
#if 0
    wzd_shm_cleanup(config->shm_key-1);
    mainConfig_shm = wzd_shm_create(config->shm_key-1,sizeof(wzd_config_t),0);
#endif
    if (mainConfig_shm == NULL) {
      fprintf(stderr,"MainConfig shared memory zone could not be created !\n");
      exit(1);
    }
  }
  created_shm=1;
  mainConfig = mainConfig_shm->datazone;
  setlib_mainConfig(mainConfig);
  memcpy(mainConfig,config,sizeof(wzd_config_t));

  if (CFG_GET_USE_SYSLOG(mainConfig)) {
    openlog("wzdftpd", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_FTP);
    // LOG_CONS - If syslog could not pass our messages they'll apear on console,
    // LOG_NDELAY - We don't want to wait for first message but open the connection to syslogd immediatly 
    // LOG_PID - We want see pid of of deamon in logfiles (Is it needed?)
  }
  else {
    fd = open(mainConfig->logfilename,mainConfig->logfilemode,0640);
    mainConfig->logfile = fdopen(fd,"a");
  }
  
#ifdef SSL_SUPPORT
  ret = tls_init();
  if (ret) {
    out_log(LEVEL_CRITICAL,"TLS subsystem could not be initialized.\n");
    return 1;
  }
#endif

  ret = runMainThread(argc,argv);

  /* we should never pass here - see wzd_ServerThread.c */

  return ret;
}
