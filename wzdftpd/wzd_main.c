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
/*! \addtogroup wzdftpd
 *  \brief Main executable group
 *  @{
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

#ifdef WIN32
#include <winsock2.h>

#include "../visual/gnu_regex/regex.h"
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

#include <libwzd-core/wzd_structs.h>

#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_tls.h>
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_configloader.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_utf8.h>

#include "wzd_opts.h"
#include "wzd_ServerThread.h"

#include <libwzd-core/wzd_debug.h>

#include "wzd_version.h"

#ifdef WIN32
int nt_service_register(void);
int nt_service_unregister(void);
int nt_service_start(void);
int nt_service_stop(void);
int nt_is_service(void);

VOID UpdateSCM( DWORD dwCurrentState , DWORD dwWaitHint , DWORD dwWin32ExitCode );
VOID MyServiceRun(DWORD argc, LPSTR *argv);
VOID MyServiceCtrlHandler(DWORD opcode);

void SvcDebugOut(const char *fmt,...);

SERVICE_STATUS              service_status;
SERVICE_STATUS_HANDLE       service_status_handle;

static int ntservice=0;
#endif

typedef enum {
  CMD_NONE=0,
#ifdef WIN32
  CMD_SRV_REGISTER,
  CMD_SRV_UNREGISTER,
  CMD_SRV_START,
  CMD_SRV_STOP,
#endif
  CMD_TEST_CONFIG,
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
  fprintf(stderr,"%s build %s (%s)\n", WZD_VERSION_LONG,WZD_BUILD_NUM,WZD_BUILD_OPTS);
  fprintf(stderr, "\nusage: wzdftpd [arguments]\n");
  fprintf(stderr,"\narguments:\r\n");
#ifdef HAVE_GETOPT_LONG
  fprintf(stderr," -h, --help                  - Display this text \n");
#if DEBUG
  fprintf(stderr," -b, --background            - Force background \n");
#endif
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s, --force-foreground      - Stay in foreground \n");
  fprintf(stderr," -t, --configtest            - Test configuration file\n");
  fprintf(stderr," -V, --version               - Show version \n");
#else /* HAVE_GETOPT_LONG */
  fprintf(stderr," -h                          - Display this text \n");
#if DEBUG
  fprintf(stderr," -b                          - Force background \n");
#endif
  fprintf(stderr," -f <file>                   - Load alternative config file \n");
  fprintf(stderr," -s                          - Stay in foreground \n");
#ifdef WIN32
  fprintf(stderr," -si                         - Register service \n");
  fprintf(stderr," -sd                         - Unregister service \n");
  fprintf(stderr," -ss                         - Start service (must be registered) \n");
  fprintf(stderr," -st                         - Stop service (must be registered) \n");
#endif
  fprintf(stderr," -V                          - Show version \n");

#endif /* HAVE_GETOPT_LONG */
}


int main_parse_args(int argc, char **argv)
{
#ifndef WIN32
  int opt;


#ifdef HAVE_GETOPT_LONG
  static struct option long_options[] =
  {
    /* Options without arguments: */
    { "background", no_argument, NULL, 'b' },
    { "config-file", required_argument, NULL, 'f' },
    { "help", no_argument, NULL, 'h' },
    { "force-foreground", no_argument, NULL, 's' },
    { "configtest", no_argument, NULL, 't' },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 } /* sentinel */
  };

  /* please keep options ordered ! */
/*  while ((opt=getopt(argc, argv, "hbdf:sV")) != -1) {*/
  while ((opt=getopt_long(argc, argv, "hbf:stV", long_options, (int *)0)) != -1)
#else /* HAVE_GETOPT_LONG */
  while ((opt=getopt(argc, argv, "hbf:stV")) != -1)
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
      exit (0);
    case 's':
      stay_foreground = 1;
      break;
    case 't':
      start_command = CMD_TEST_CONFIG;
      break;
    case 'V':
      fprintf(stderr,"%s build %s (%s)\n",
          WZD_VERSION_LONG,WZD_BUILD_NUM,WZD_BUILD_OPTS);
      exit (0);
    }
  }
#else /* WIN32 */
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
        exit (0);
      }
      if (!strcmp(argv[optindex],"-V")) {
        fprintf(stderr,"%s build %s (%s)\n",
            WZD_VERSION_LONG,WZD_BUILD_NUM,WZD_BUILD_OPTS);
        exit (0);
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
      if (!strcmp(argv[optindex],"-t")) {
        start_command = CMD_TEST_CONFIG;
        optindex++;
        continue;
      }
      if (!strcmp(argv[optindex],"-service")) {
        ntservice = 1;
        optindex++;
        continue;
      }
      break;
    }
  }
#endif /* WIN32 */
  return 0;
}



int main(int argc, char **argv)
{
  int ret, i;
  pid_t forkresult;
  wzd_config_t * config;
  wzd_configfile_t * cf;

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
      out_err(LEVEL_CRITICAL,"Error while parsing args, aborting\n");
      return 0;
    }
    config_files[0] = configfile_name;

    switch (start_command) {
#ifdef WIN32
      case CMD_SRV_UNREGISTER:
        nt_service_unregister();
        exit (0);
      case CMD_SRV_START:
        nt_service_start();
        exit (0);
      case CMD_SRV_STOP:
        nt_service_stop();
        exit (0);
#endif
      case CMD_TEST_CONFIG:
        {
          const char * test_config = NULL;
          /* try new config file format first */
          cf = config_new();
          for (i=0; config_files[i]; i++) {
            if (config_files[i][0]!='\0') { test_config = config_files[i]; break; }
          }
          if (test_config == NULL) {
            out_err(LEVEL_CRITICAL,"Could not find ANY config file !\n");
            out_err(LEVEL_CRITICAL,"Try restarting with command -f <config>\n");
            exit (1);
          }
          out_err(LEVEL_NORMAL,"Testing configuration file %s\n",test_config);
          ret = config_load_from_file (cf, test_config, 0);
          if (!ret) {
            int err;

            out_err(LEVEL_INFO,"config: NEW format found [%s]\n",config_files[i]);

            config = cfg_store(cf,&err);
            if (config) {
              out_err(LEVEL_NORMAL,"*** Configuration test OK ***\n");
              exit (0);
            }
          }
          out_err(LEVEL_CRITICAL,"ERROR: could NOT load config file %s\n",test_config);
          config_free(cf);
        }
        exit (-1);
      default:
        break;
    }
  }

  if (!stay_foreground) {
#ifndef WIN32
    forkresult = fork();
#else
    forkresult = 0;
#endif

    if ((int)forkresult == -1)
      fprintf(stderr,"Could not fork into background\n");
    if ((int)forkresult != 0)
      exit(0);
  }

  /* initialize random seed */
  srand((unsigned int)(time(NULL)+0x13313043));

  /* not really usefull, but will also initialize var if not used :) */
#ifndef WIN32
  setlib_server_uid(geteuid());
#endif

  /* initialize logging facilities */
  if (log_init()) {
    fprintf(stderr,"FATAL: Couldn't init logging facilities, aborting\n");
    exit(1);
  }

  /* default server messages */
  init_default_messages();

  /* config file */
  config = NULL;

  for (i=0; config_files[i]; i++)
  {
    /* try new config file format first */
    cf = config_new();
    ret = config_load_from_file (cf, config_files[i], 0);
    if (!ret) {
      int err;

      out_err(LEVEL_INFO,"config: NEW format found [%s]\n",config_files[i]);

      config = cfg_store(cf,&err);
      if (config) {
        /* cf will NOT be freed at this point, it is stored into config */
        break;
      }
    }
    config_free(cf);
    if (!ret) break;
  }
  if (!config) {
    fprintf(stderr,"FATAL: No valid config file found, aborting !\n");
    exit(1);
  }


  if (!config) {
    out_err(LEVEL_CRITICAL,"FATAL: Critical error loading config file, aborting\n");
    exit(1);
  }

  config->config_filename = wzd_strdup(config_files[i]);


  /* \todo XXX use values given in command-line ? */
  switch (start_command) {
    case CMD_NONE:
      break;
#ifdef WIN32
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
    default:
      break;
  }


  mainConfig = config;
  setlib_mainConfig(mainConfig);

#ifndef WIN32
  if (CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG)) {
    openlog("wzdftpd", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_FTP);
    // LOG_CONS - If syslog could not pass our messages they'll apear on console,
    // LOG_NDELAY - We don't want to wait for first message but open the connection to syslogd immediatly 
    // LOG_PID - We want see pid of of deamon in logfiles (Is it needed?)
    for (i=0; i<MAX_LOG_CHANNELS; i++)
      log_set_syslog(i,1);
  }
#endif
  if (mainConfig->logfilename != NULL) {
    ret = log_open(mainConfig->logfilename,mainConfig->logfilemode);
    if (ret < 0) {
      /* stderr is not closed here, even in release mode */
      fprintf(stderr,"FATAL: Could not open log file %s\n",mainConfig->logfilename);
      return 1;
    }
    /** \todo this should be removed (as well as log_get() function) and replace
     * with a proper init code
     */
    for (i=0; i<MAX_LOG_CHANNELS; i++) {
      if (log_get(i) == -1)
        log_set(i,ret);
    }
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  ret = tls_init();
  if (ret) {
    out_log(LEVEL_CRITICAL,"TLS subsystem could not be initialized.\n");
    return 1;
  }
#endif

  utf8_detect(mainConfig);

#if defined(DEBUG) || !defined(WIN32)
  ret = runMainThread(argc,argv);
#else
  if (ntservice)
  {
    SERVICE_TABLE_ENTRY DispatchTable[] = {
      { "wzdftpd", (LPSERVICE_MAIN_FUNCTION)MyServiceRun },
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

#ifdef WIN32

/** \brief Report the status to the service manager */
VOID UpdateSCM(DWORD dwCurrentState, DWORD dwWaitHint, DWORD dwWin32ExitCode)
{
  DWORD status;

  service_status.dwServiceType = SERVICE_WIN32;
  service_status.dwCurrentState = dwCurrentState;
  service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  service_status.dwWin32ExitCode = dwWin32ExitCode;
  service_status.dwServiceSpecificExitCode = 0;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = dwWaitHint;

  /* report status */
  if (!SetServiceStatus(service_status_handle, &service_status)){
    status = GetLastError();
    SvcDebugOut(" [wzdftpd] SetServiceStatus %d error %d\n",dwCurrentState,GetLastError() );
  }
}

VOID MyServiceRun(DWORD argc, LPSTR *argv)
{
  int ret;
 
  service_status_handle = RegisterServiceCtrlHandler(  "wzdftpd",  (LPHANDLER_FUNCTION)MyServiceCtrlHandler);
  if (!service_status_handle){
    SvcDebugOut( "[wzdftpd] RegisterServiceCtrlHandler error = %d\n", GetLastError() );
    return;
  }

  /* report start pending status */
  UpdateSCM( SERVICE_START_PENDING , 0 , 0 );
  
  /* Actually there should pass some time/stuff between reporting the pending and running status */
  UpdateSCM( SERVICE_RUNNING , 0 , 0 );
  /* This is where the service does its work */
  SvcDebugOut("[wzdftpd] Going to run main thread\n");
  ret = runMainThread(argc,argv);

  SvcDebugOut("[wzdftpd] Reported SERVICE_STOPPED\n");
  /* report stopped status */
  UpdateSCM( SERVICE_STOPPED , 0, 0 );
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
      UpdateSCM( SERVICE_STOP_PENDING , 5000 , 0 );
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
  if (!SetServiceStatus(service_status_handle,&service_status)) {
    status = GetLastError();
    SvcDebugOut(" [wzdftpd] SetServiceStatus error %ld\n",status);
  }
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

  snprintf(startcmd,MAX_PATH,"%s -f \"%s\" -service",binaryPathName,config_fullpath);

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

void SvcDebugOut(const char *fmt,...)
{
  va_list argptr;
  char buffer[4096];

  va_start(argptr,fmt);
  vsnprintf(buffer,1024,fmt,argptr);
  va_end(argptr);

  OutputDebugStringA(buffer);
}

#endif /* WIN32 */

/*! @} */
