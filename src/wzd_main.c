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
/** \file wzd_main.c
  * \brief Startup code: check args, load config file and start main thread.
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
#include <time.h>

#ifdef _MSC_VER
#include <winsock2.h>

#include "../visual/gnu_regex_dist/regex.h"
#else
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <regex.h>

#include <syslog.h>

#if defined(__sun__)
# define LOG_FTP LOG_DAEMON
#endif

#endif

#include <errno.h>
#include <fcntl.h>

#include "wzd_structs.h"

#include "wzd_misc.h"
#include "wzd_log.h"
#include "wzd_tls.h"
#include "wzd_init.h"
#include "wzd_libmain.h"
#include "wzd_ServerThread.h"
#include "wzd_opts.h"
#include "wzd_utf8.h"

#include "wzd_debug.h"

#ifdef _MSC_VER
int nt_service_register(void);
int nt_service_unregister(void);
int nt_service_start(void);
int nt_service_stop(void);
int nt_is_service(void);
void SvcDebugOut(LPSTR string, DWORD status);
VOID MyServiceStart(DWORD argc, LPSTR *argv);
VOID MyServiceCtrlHandler(DWORD opcode);
DWORD MyServiceInitialization(DWORD argc, LPSTR *argv, DWORD *specificError);

SERVICE_STATUS              service_status;
SERVICE_STATUS_HANDLE       service_status_handle;
#endif

typedef enum {
  CMD_NONE=0,
#ifdef _MSC_VER
  CMD_SRV_REGISTER,
  CMD_SRV_UNREGISTER,
  CMD_SRV_START,
  CMD_SRV_STOP,
#endif
} wzd_arg_command_t;

char configfile_name[256];
int stay_foreground=0;
static wzd_arg_command_t start_command=CMD_NONE;

static const char * config_files[] = {
  "",
  WZD_DEFAULT_CONF,
  "wzd.cfg",
  "/etc/wzdftpd/wzd.cfg",
  "/etc/wzd.cfg",
  "/usr/local/etc/wzd.cfg",
  NULL /* do NOT remove */
};

void display_usage(void)
{
  fprintf(stderr,"%s build %s (%s)\n", WZD_VERSION_STR,WZD_BUILD_NUM,WZD_BUILD_OPTS);
  fprintf(stderr, "\nusage: wzdftpd [arguments]\n");
  fprintf(stderr,"\narguments:\r\n");
#ifdef HAVE_GETOPT_LONG
  fprintf(stderr," -h, --help                  - Display this text \n");
#if DEBUG
  fprintf(stderr," -b, --background            - Force background \n");
#endif
  fprintf(stderr," -d,                         - Delete IPC if present (Linux only) \n");
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s, --force-foreground      - Stay in foreground \n");
  fprintf(stderr," -V, --version               - Show version \n");
#else /* HAVE_GETOPT_LONG */
  fprintf(stderr," -h                          - Display this text \n");
#if DEBUG
  fprintf(stderr," -b                          - Force background \n");
#endif
  fprintf(stderr," -d,                         - Delete IPC if present (Linux only) \n");
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s                          - Stay in foreground \n");
#ifdef _MSC_VER
  fprintf(stderr," -si                         - Register service \n");
  fprintf(stderr," -sd                         - Unregister service \n");
  fprintf(stderr," -ss                         - Start service (must be registered) \n");
  fprintf(stderr," -st                         - Stop service (must be registered) \n");
#endif
  fprintf(stderr," -V                          - Show version \n");

#endif /* HAVE_GETOPT_LONG */
}

static wzd_config_t * load_config_file(const char *name, wzd_config_t ** config)
{
  *config = readConfigFile(name);

  return *config;
}


int main_parse_args(int argc, char **argv)
{
#ifndef _MSC_VER
  int opt;


#ifdef HAVE_GETOPT_LONG
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
  while ((opt=getopt_long(argc, argv, "hbf:sV", long_options, (int *)0)) != -1)
#else /* HAVE_GETOPT_LONG */
  while ((opt=getopt(argc, argv, "hbf:sV")) != -1)
#endif /* HAVE_GETOPT_LONG */
  {
    switch((char)opt) {
    case 'b':
      stay_foreground = 0;
      break;
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
      fprintf(stderr,"%s build %s (%s)\n",
          WZD_VERSION_STR,WZD_BUILD_NUM,WZD_BUILD_OPTS);
      return 1;
    }
  }
#else /* _MSC_VER */
  if (argc > 1) {
    int optindex=1;
    while (optindex < argc) {
      if (!strcmp(argv[optindex],"-f")) {
        optindex++;
        if (optindex < argc) {
          if (strlen(argv[optindex])>=255) {
            fprintf(stderr,"filename too long (>255 chars)\n");
            return 1;
          }
          strncpy(configfile_name,argv[optindex],255);
          optindex++;
        } else {
          fprintf(stderr,"missing filename after -f option\n");
          return 1;
        }
        continue;
      }
      if (!strcmp(argv[optindex],"-b")) {
        stay_foreground = 0;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-s")) {
        stay_foreground = 1;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-h")) {
        display_usage();
        return 1;
      }
      if (!strcmp(argv[optindex],"-V")) {
        fprintf(stderr,"%s build %s (%s)\n",
            WZD_VERSION_STR,WZD_BUILD_NUM,WZD_BUILD_OPTS);
        return 1;
      }
      if (!strcmp(argv[optindex],"-si")) {
        start_command = CMD_SRV_REGISTER;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-sd")) {
        start_command = CMD_SRV_UNREGISTER;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-ss")) {
        start_command = CMD_SRV_START;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-st")) {
        start_command = CMD_SRV_STOP;
        optindex++;
        continue;
      }
      break;
    }
  }
#endif /* _MSC_VER */
  return 0;
}



int main(int argc, char **argv)
{
  int ret, i;
  pid_t forkresult;
  wzd_config_t * config;

  wzd_debug_init();

#if 0
  fprintf(stderr,"--------------------------------------\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"This is a beta release, in active development\n");
  fprintf(stderr,"Things may break from version to version\n");
  fprintf(stderr,"Want stability ? Use a 0.4 version. YOU WERE WARNED!\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"--------------------------------------\n");
  fprintf(stderr,"\n");
#endif

#if DEBUG
  stay_foreground = 1;
#endif
  /* default value */
/*  strcpy(configfile_name,"wzd.cfg");*/
  configfile_name[0]='\0';

  if (argc > 1) {
    ret = main_parse_args(argc,argv);
    if (ret) {
      return 0;
    }
#ifdef _MSC_VER
    switch (start_command) {
      case CMD_SRV_UNREGISTER:
        nt_service_unregister();
        exit (0);
      case CMD_SRV_START:
        nt_service_start();
        exit (0);
      case CMD_SRV_STOP:
        nt_service_stop();
        exit (0);
    }
#endif
  }

  if (!stay_foreground) {
#ifndef _MSC_VER
    forkresult = fork();
#else
    forkresult = 0;
#endif

    if ((int)forkresult == -1)
      out_err(LEVEL_CRITICAL,"Could not fork into background\n");
    if ((int)forkresult != 0)
      exit(0);
  }

  /* initialize random seed */
  srand((unsigned int)(time(NULL)+0x13313043));

  /* not really usefull, but will also initialize var if not used :) */
#ifndef WIN32
  setlib_server_uid(geteuid());
#endif

  config = NULL;
  config_files[0] = configfile_name;

  for (i=0; config_files[i]; i++)
  {
    if (load_config_file(config_files[i],&config)) break;
  }
  if (!config) {
    fprintf(stderr,"No valid config file found, aborting !\n");
    exit(1);
  }


  if (!config) {
    out_err(LEVEL_CRITICAL,"Critical error loading config file, aborting\n");
    exit(1);
  }

  config->config_filename = wzd_strdup(config_files[i]);


  /* \todo XXX use values given in command-line ? */
  switch (start_command) {
    case CMD_NONE:
      break;
#ifdef _MSC_VER
    case CMD_SRV_REGISTER:
      mainConfig = config;
      nt_service_register();
      exit (0);
    case CMD_SRV_UNREGISTER:
      mainConfig = config;
      nt_service_unregister();
      exit (0);
    case CMD_SRV_START:
      mainConfig = config;
      nt_service_start();
      exit (0);
    case CMD_SRV_STOP:
      mainConfig = config;
      nt_service_stop();
      exit (0);
#endif
  }


  mainConfig = wzd_malloc(sizeof(wzd_config_t));


  setlib_mainConfig(mainConfig);
  memcpy(mainConfig,config,sizeof(wzd_config_t));

#ifndef WIN32
  if (CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG)) {
    openlog("wzdftpd", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_FTP);
    // LOG_CONS - If syslog could not pass our messages they'll apear on console,
    // LOG_NDELAY - We don't want to wait for first message but open the connection to syslogd immediatly 
    // LOG_PID - We want see pid of of deamon in logfiles (Is it needed?)
  }
#endif
  if (log_open(mainConfig->logfilename,mainConfig->logfilemode))
  {
    out_err(LEVEL_CRITICAL,"Could not open log file.\n");
    return 1;
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  ret = tls_init();
  if (ret) {
    out_log(LEVEL_CRITICAL,"TLS subsystem could not be initialized.\n");
    return 1;
  }
#endif

  utf8_detect(mainConfig);

#if defined(DEBUG) || !defined(_MSC_VER)
  ret = runMainThread(argc,argv);
#else
  if (nt_is_service())
  {
    SERVICE_TABLE_ENTRY         DispatchTable[] = 
    {
      { "wzdftpd", (LPSERVICE_MAIN_FUNCTION)MyServiceStart },
      { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcher(DispatchTable))
      SvcDebugOut( "[wzdftpd] StartServiceCtrlDispatcher error = %d\n", GetLastError());
  }
  else
    ret = runMainThread(argc,argv);
#endif

  /* we should never pass here - see wzd_ServerThread.c */

  return ret;
}

#ifdef _MSC_VER

VOID MyServiceStart(DWORD argc, LPSTR *argv)
{
  DWORD status;
  DWORD specificError;

  service_status.dwServiceType = SERVICE_WIN32;
  service_status.dwCurrentState = SERVICE_START_PENDING;
  service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
  service_status.dwWin32ExitCode = 0;
  service_status.dwServiceSpecificExitCode = 0;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = 0;

  service_status_handle = RegisterServiceCtrlHandler(
    "wzdftpd",
    (LPHANDLER_FUNCTION)MyServiceCtrlHandler);

  if (service_status_handle == (SERVICE_STATUS_HANDLE)0) {
    SvcDebugOut( "[wzdftpd] RegisterServiceCtrlHandler error = %d\n", GetLastError());
    return;
  }

  /* initialization goes here */
  status = MyServiceInitialization(argc,argv,&specificError);

  /* handle error code */

  /* report running status */
  service_status.dwCurrentState = SERVICE_RUNNING;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = 0;

  if (!SetServiceStatus(service_status_handle, &service_status))
  {
    status = GetLastError();
    SvcDebugOut(" [wzdftpd] SetServiceStatus error %ld\n",status);
  }

  /* This is where the service does its work */
  SvcDebugOut(" [wzdftpd] returning to main thread\n",0);
  runMainThread(argc,argv);
}

VOID MyServiceCtrlHandler(DWORD opcode)
{
  DWORD status;

  switch(opcode)
  {
    case SERVICE_CONTROL_PAUSE:
      break;
    case SERVICE_CONTROL_CONTINUE:
      break;
    case SERVICE_CONTROL_STOP:
      mainConfig->serverstop = 1;

      service_status.dwCurrentState = SERVICE_STOPPED;
      service_status.dwWin32ExitCode = 0;
      service_status.dwServiceSpecificExitCode = 0;
      service_status.dwCheckPoint = 0;
      service_status.dwWaitHint = 0;

      if (!SetServiceStatus(service_status_handle, &service_status))
      {
        status = GetLastError();
        SvcDebugOut(" [wzdftpd] SetServiceStatus error %ld\n",status);
      }
      SvcDebugOut(" [wzdftpd] exiting\n",0);

      return;
    case SERVICE_CONTROL_INTERROGATE:
      /* fall through to send current status */
      break;
    default:
      SvcDebugOut(" [wzdftpd] Unrecognized opcode %ld\n",opcode);
      break;
  }

  /* send current status */
  if (!SetServiceStatus(service_status_handle,&service_status))
  {
    status = GetLastError();
    SvcDebugOut(" [wzdftpd] SetServiceStatus error %ld\n",status);
  }
}

DWORD MyServiceInitialization(DWORD argc, LPSTR *argv, DWORD *specificError)
{
  specificError = 0;
  return 0;
}

int nt_is_service(void)
{
  SC_HANDLE schService, schSCManager;
  int is_service;

  /* obtain a handler to the SC Manager database */
  schSCManager = OpenSCManager(
      NULL,     /* local machine */
      NULL,     /* ServicesActive database */
      SC_MANAGER_ALL_ACCESS); /* full access rights */

  if (schSCManager == NULL) return -1;

  schService = OpenService(
      schSCManager,             /* SCManager database */
      "wzdftpd",                /* name of service */
      SERVICE_ALL_ACCESS);

  is_service = (schService != NULL);

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  return is_service;
}

int nt_service_register(void)
{
  SC_HANDLE schService, schSCManager;
  LPCTSTR binaryPathName;
  char buffer[MAX_PATH+1];
  char config_fullpath[MAX_PATH+1];
  char startcmd[MAX_PATH+1];

  if ( !mainConfig || !mainConfig->config_filename ||
    !_fullpath(config_fullpath,mainConfig->config_filename,MAX_PATH) ) {
    fprintf(stderr,"fullpath failed %d\n",GetLastError());
    return -1;
  }

  /* obtain a handler to the SC Manager database */
  schSCManager = OpenSCManager(
      NULL,     /* local machine */
      NULL,     /* ServicesActive database */
      SC_MANAGER_ALL_ACCESS); /* full access rights */

  if (schSCManager == NULL) return -1;

  GetModuleFileName(NULL,buffer,sizeof(buffer));
  binaryPathName = buffer;

  snprintf(startcmd,MAX_PATH,"%s -f \"%s\"",binaryPathName,config_fullpath);

  schService = CreateService(
      schSCManager,             /* SCManager database */
      "wzdftpd",                /* name of service */
      "wzdftpd",                /* service name to display */
      SERVICE_ALL_ACCESS,       /* desired access */
      SERVICE_WIN32_OWN_PROCESS,/* service type */
      SERVICE_DEMAND_START,     /* start type */
      SERVICE_ERROR_NORMAL,     /* error control type */
      startcmd,                 /* service's binary */
      NULL,                     /* no load ordering group */
      NULL,                     /* no tag identifier */
      NULL,                     /* no dependancies */
      NULL,                     /* LocalSystem account */
      NULL);                    /* no password */

  if (schService == NULL) {
    fprintf(stderr,"CreateService failed %d\n",GetLastError());
    CloseServiceHandle(schSCManager);
    return -1;
  }




  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  
  return 0;
}

int nt_service_unregister(void)
{
  SC_HANDLE schService, schSCManager;

  /* obtain a handler to the SC Manager database */
  schSCManager = OpenSCManager(
      NULL,     /* local machine */
      NULL,     /* ServicesActive database */
      SC_MANAGER_ALL_ACCESS); /* full access rights */

  if (schSCManager == NULL) return -1;

  schService = OpenService(
      schSCManager,             /* SCManager database */
      "wzdftpd",                /* name of service */
      DELETE);                  /* only need DELETE access */

  if (schService == NULL) {
    fprintf(stderr,"OpenService failed %d\n",GetLastError());
    CloseServiceHandle(schSCManager);
    return -1;
  }

  if (!DeleteService(schService)) {
    fprintf(stderr,"DeleteService failed %d\n",GetLastError());
    CloseServiceHandle(schSCManager);
    return -1;
  }

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  
  return 0;
}

int nt_service_start(void)
{
  SC_HANDLE schService, schSCManager;
  SERVICE_STATUS ssStatus;
  DWORD dwOldCheckPoint;
  DWORD dwStartTickCount;
  DWORD dwWaitTime;

  /* obtain a handler to the SC Manager database */
  schSCManager = OpenSCManager(
      NULL,     /* local machine */
      NULL,     /* ServicesActive database */
      SC_MANAGER_ALL_ACCESS); /* full access rights */

  if (schSCManager == NULL) return -1;

  schService = OpenService(
      schSCManager,             /* SCManager database */
      "wzdftpd",                /* name of service */
      SERVICE_ALL_ACCESS);

  if (schService == NULL) {
    fprintf(stderr,"OpenService failed %d\n",GetLastError());
    CloseServiceHandle(schSCManager);
    return -1;
  }

  if (!StartService(
        schService,     /* handle to service */
        0,              /* number of arguments */
        NULL))          /* no arguments */
  {
    fprintf(stderr,"Service started\n");
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return 0;
  } else {
    fprintf(stderr,"Service start pending\n");

    /* check the status until the service is no longer start pending */
    if (!QueryServiceStatus(
          schService,   /* handle to service */
          &ssStatus))   /* address of status information structure */
    {
      CloseServiceHandle(schSCManager);
      return -1;
    }

    /* save the tick count and initial checkpoint */
    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = ssStatus.dwCheckPoint;

    while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
    {
      /* do not wait longer than the wait hint. A good interval is
       * one tenth the wait hint, but no less than 1 second and no
       * more than 10 seconds
       */
      dwWaitTime = ssStatus.dwWaitHint / 10;
      if (dwWaitTime < 1000)
        dwWaitTime = 1000;
      else if (dwWaitTime > 10000)
        dwWaitTime = 10000;

      Sleep(dwWaitTime);

      /* check the status again */
      if (!QueryServiceStatus(
            schService,   /* handle to service */
            &ssStatus))   /* address of status information structure */
        break;

      fprintf(stderr,".");
      fflush(stderr);

      if (ssStatus.dwCheckPoint > dwOldCheckPoint)
      {
        /* the service is making progress */
        dwStartTickCount = GetTickCount();
        dwOldCheckPoint = ssStatus.dwCheckPoint;
      } else {
        if (GetTickCount()-dwStartTickCount > ssStatus.dwWaitHint)
        {
          /* no progress made withiin the wait hint */
          break;
        }
      }
    }
    
  }

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  if (ssStatus.dwCurrentState == SERVICE_RUNNING)
  {
    fprintf(stderr,"Service started.\n");
  } else {
    fprintf(stderr,"Service not started\n");
  }
 
  return 0;
}

int nt_service_stop(void)
{
  SC_HANDLE schService, schSCManager;
  SERVICE_STATUS ssStatus;
  DWORD dwStartTime;
  DWORD dwTimeout;

  /* obtain a handler to the SC Manager database */
  schSCManager = OpenSCManager(
      NULL,     /* local machine */
      NULL,     /* ServicesActive database */
      SC_MANAGER_ALL_ACCESS); /* full access rights */

  if (schSCManager == NULL) return -1;

  schService = OpenService(
      schSCManager,             /* SCManager database */
      "wzdftpd",                /* name of service */
      SERVICE_ALL_ACCESS);

  if (schService == NULL) {
    fprintf(stderr,"OpenService failed %d\n",GetLastError());
    CloseServiceHandle(schSCManager);
    return -1;
  }
  dwStartTime = GetTickCount();
  dwTimeout = 10000; /* 10s */

  if (!QueryServiceStatus( schService, &ssStatus))
    return GetLastError();

  if (ssStatus.dwCurrentState == SERVICE_STOPPED) {
    fprintf(stderr,"Service already stopped\n");
    return 0;
  }

  /* if a stop is pending, just wait for it */
  while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
  {
    Sleep(ssStatus.dwWaitHint);

    if (!QueryServiceStatus( schService, &ssStatus))
      return GetLastError();

    if (GetTickCount()-dwStartTime > dwTimeout) {
      fprintf(stderr,"Timeout\n");
      return -1;
    }
  }

  if (!ControlService( schService, SERVICE_CONTROL_STOP, &ssStatus))
    return GetLastError();

  /* wait for the service to stop */
  while (ssStatus.dwCurrentState != SERVICE_STOPPED)
  {
    Sleep(ssStatus.dwWaitHint);

    if (!QueryServiceStatus( schService, &ssStatus))
      return GetLastError();

    if (GetTickCount()-dwStartTime > dwTimeout) {
      fprintf(stderr,"Timeout\n");
      return -1;
    }
  }

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  if (ssStatus.dwCurrentState == SERVICE_STOPPED)
  {
    fprintf(stderr,"Service stopped.\n");
  } else {
    fprintf(stderr,"Service not stopped\n");
  }
 
  return 0;
}

void SvcDebugOut(LPSTR string, DWORD status)
{
  CHAR buffer[1024];
  snprintf(buffer,1024,string,status);
  OutputDebugStringA(buffer);
}

#endif /* _MSC_VER */
