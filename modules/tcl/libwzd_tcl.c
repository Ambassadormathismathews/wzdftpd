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

/* XXX FIXME
 * IMPORTANT NOTES: this module does not like unloading,
 * it provokes a segfault at thread exit
 * This seems to be a problem between threads and shared libs.
 */
/* XXX FIXME
 * the following code is NOT reentrant at all
 * I should use locks and/or use interpreter slaves
 */

/* URL: http://aspn.activestate.com/ASPN/docs/ActiveTcl/tcl/tcl_13_contents.htm
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <io.h>

#include "../../visual/gnu_regex/regex.h"
#else
#include <dirent.h>
#include <sys/types.h>
#include <regex.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>



#include <tcl.h>

/*#include <wzd.h>*/
#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_configfile.h> /* server configuration */
#include <libwzd-core/wzd_file.h> /* file_mkdir, file_stat */
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_mod.h> /* essential to define WZD_MODULE_INIT */
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_vfs.h> /* checkpath_new */
#include <libwzd-core/wzd_vars.h> /* needed to access variables */

#include <libwzd-core/wzd_debug.h>

/***** Private vars ****/
static Tcl_Interp * interp=NULL;
static wzd_context_t * current_context=NULL;

static int tcl_fd_errlog=-1;

#define TCL_ARGS        "wzd_args"
#define TCL_CURRENT_USER "wzd_current_user"
#define TCL_REPLY_CODE  "wzd_reply_code"
#define TCL_HAS_REPLIED "wzd_replied"
#define TCL_WZD_RETURN "wzd_return"
#define TCL_ERRORLOGNAME "tclerr.log"

#define WZDOUT  ((ClientData)1)
#define WZDERR  ((ClientData)2)

/***** Private fcts ****/
static void do_tcl_help(wzd_context_t * context);
static int tcl_diagnose(void);


static int channel_close(ClientData instance, Tcl_Interp *interp);
static int channel_input(ClientData instance, char *buf, int bufsiz, int *errptr);
static int channel_output(ClientData instance, const char *buf, int bufsiz, int *errptr);
static void channel_watch(ClientData instance, int mask);
static int channel_gethandle(ClientData instance, int direction, ClientData *handleptr);

/***** Private structs ****/

static Tcl_ChannelType channel_type =
{
  "wzdmessage",
  TCL_CHANNEL_VERSION_2,
  channel_close,
  channel_input,
  channel_output,
  NULL,   /* seek */
  NULL,   /* set option */
  NULL,   /* get option */
  channel_watch,
  channel_gethandle,
  NULL,   /* close2 */
  NULL,   /* block */
  NULL,   /* flush */
  NULL,   /* handler */
  NULL,   /* wideseek */
#ifdef TCL_CHANNEL_VERSION_4
  NULL,   /* threadActionProc */
#endif
};

/***** EVENT HOOKS *****/
static event_reply_t tcl_event_logout(const char * args);

static int do_site_tcl(wzd_string_t *name, wzd_string_t *param, wzd_context_t *context);

/***** PROTO HOOKS *****/
static int tcl_hook_protocol(const char *file, const char *args);

/***** TCL commands ****/
static int tcl_chgrp(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_chmod(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_chown(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_ftp2sys(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_killpath(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_putlog(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_send_message(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_send_message_raw(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_stat(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_group(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_shm(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_user(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vfs(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);

/***** slaves *****/
static Tcl_Interp * _tcl_getslave(Tcl_Interp *interp, void *context);


/***********************/
MODULE_NAME(tcl);
MODULE_VERSION(106);

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
  static Tcl_Channel ch1, ch2;
#ifdef _MSC_VER
  {
    char buffer[MAX_PATH+1];
    char *p;

    GetModuleFileName(NULL,buffer,sizeof(buffer));
    /* converts path to tcl format */
    for (p=buffer; *p!='\0'; p++) {
      if (*p=='\\') *p = '/';
    }
    Tcl_FindExecutable(buffer);
  }
#else
  Tcl_FindExecutable("wzdftpd");
#endif /* _MSC_VER */

  if (tcl_diagnose())
  {
    out_log(LEVEL_HIGH, "TCL: self-test failed, disabling TCL\n");
    return -1;
  }

  interp = Tcl_CreateInterp();
  if (!interp) {
    out_log(LEVEL_HIGH,"TCL could not create interpreter\n");
    return -1;
  }

  {
    char * logdir;
    int ret;

    ret = -1;
    {
      wzd_string_t * str;
      str = config_get_string(mainConfig->cfg_file, "GLOBAL", "logdir", NULL);
      if (str) {
        /** \bug FIXME memory leak here !! */
        logdir = strdup(str_tochar(str));
        str_deallocate(str);
      }
    }
    {
      int fd;

      wzd_string_t *str = str_allocate();
      str_sprintf(str,"%s/%s", logdir, TCL_ERRORLOGNAME);
      fd = open(str_tochar(str),O_CREAT|O_WRONLY,S_IRUSR | S_IWUSR);
      if (fd >= 0) {
        tcl_fd_errlog = fd;
        ret = 0;
      }
      str_deallocate(str);
    }
    if (ret) {
      out_log(LEVEL_HIGH,"tcl: i found no 'logdir' in your config file\n");
      out_log(LEVEL_HIGH,"tcl: this means I will be unable to log TCL errors\n");
      out_log(LEVEL_HIGH,"tcl: please refer to the 'logdir' config directive in help\n");
    }
  }

  /* replace stdout and stderr */
  ch1 = Tcl_CreateChannel(&channel_type, "wzdout", WZDOUT, TCL_WRITABLE);
  ch2 = Tcl_CreateChannel(&channel_type, "wzderr", WZDERR, TCL_WRITABLE);

  Tcl_SetChannelOption(interp, ch1, "-buffering", "line");
  Tcl_SetChannelOption(interp, ch2, "-buffering", "line");

  Tcl_SetStdChannel(ch1, TCL_STDOUT);
  Tcl_SetStdChannel(ch2, TCL_STDERR);

/*  Tcl_RegisterChannel(interp, ch1);
  Tcl_RegisterChannel(interp, ch2);*/

  /** It's a bit stupid to modify things here, because modifications (like changing
   * standard channels) are NOT inherited by slaves.
   */



  Tcl_CreateCommand(interp,"chgrp",tcl_chgrp,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"chmod",tcl_chmod,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"chown",tcl_chown,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"ftp2sys",tcl_ftp2sys,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"killpath",tcl_killpath,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"putlog",tcl_putlog,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"send_message",tcl_send_message,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"send_message_raw",tcl_send_message_raw,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"stat",tcl_stat,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars",tcl_vars,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_group",tcl_vars_group,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_shm",tcl_vars_shm,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_user",tcl_vars_user,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vfs",tcl_vfs,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);

  {
    const char * command_name = "site_tcl";
    /* add custom command */
    if (commands_add(getlib_mainConfig()->commands_list,command_name,do_site_tcl,NULL,TOK_CUSTOM)) {
      out_log(LEVEL_HIGH,"ERROR while adding custom command: %s\n",command_name);
    }

    /* default permission XXX hardcoded */
    if (commands_set_permission(getlib_mainConfig()->commands_list,command_name,"+O")) {
      out_log(LEVEL_HIGH,"ERROR setting default permission to custom command %s\n",command_name);
      /** \bug XXX remove command from   config->commands_list */
    }
  }

  event_connect_function(getlib_mainConfig()->event_mgr,EVENT_LOGOUT,tcl_event_logout,NULL);
  hook_add_protocol("tcl:",4,&tcl_hook_protocol);
  out_log(LEVEL_INFO,"TCL module loaded\n");
  return 0;
}

/** \bug XXX Tcl_DeleteInterp() seems to trigger some badness in channels
 * (error is: FlushChannel: damaged channel list)
 * so we temporarily disable it ...
 */
void WZD_MODULE_CLOSE(void)
{
/*  if (!Tcl_InterpDeleted(interp))
    Tcl_DeleteInterp(interp);*/
/*  Tcl_Release(interp);*/
  interp = NULL;
/*  Tcl_Exit(0);*/
  Tcl_Finalize();
  if (tcl_fd_errlog >= 0) {
    close(tcl_fd_errlog);
    tcl_fd_errlog = -1;
  }
  out_log(LEVEL_INFO,"TCL module unloaded\n");
}



static int do_site_tcl(wzd_string_t *name, wzd_string_t *param, wzd_context_t *context)
{
  if (!param || str_length(param)==0) { do_tcl_help(context); return EVENT_HANDLED; }
  {
    Tcl_Obj * TempObj;
    Tcl_Interp * slave = NULL;
    const char *s;
    char * errorinfo;
    wzd_user_t * user;
    int ret;

    slave = _tcl_getslave(interp, context);
    if (!slave) {
      send_message_with_args(501,context,"TCL: could not set slave");
      return -1;
    }

    /* send reply header */
    send_message_raw("200-\r\n",context);

    current_context = context;
    user = GetUserByID(context->userid);
    Tcl_SetVar(slave,TCL_HAS_REPLIED,"0",TCL_GLOBAL_ONLY);
    Tcl_SetVar(slave,TCL_REPLY_CODE,"200",TCL_GLOBAL_ONLY);
    Tcl_SetVar(slave,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);
    TempObj = Tcl_NewStringObj(str_tochar(param),-1);
    ret = Tcl_EvalObj(slave, TempObj);
    /* XXX FIXME should we call Tcl_DecrRefCount() ? */
    current_context = NULL;
    s = Tcl_GetVar(slave,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
    if (!s || *s!='1') {
      if (ret != TCL_OK) {
        errorinfo = (char *) Tcl_GetVar(interp, "errorInfo", 0);
        out_err(LEVEL_HIGH,"TCL error: %s\n",errorinfo);
        send_message_with_args(200,context,"Error in TCL command");
      } else
        send_message_with_args(200,context,"TCL command ok");
    }
  }
  return 0;
}

static event_reply_t tcl_event_logout(const char * args)
{
  Tcl_Interp * slave = NULL;
  wzd_context_t * context = GetMyContext();

  char buffer[64];
  snprintf(buffer, 64, "%p", context);

  if ( (slave = Tcl_GetSlave(interp, buffer)) )
  {
    if (!Tcl_InterpDeleted(slave))
      Tcl_DeleteInterp(slave);
    Tcl_Release(slave);
  }

  return EVENT_OK;
}

static int tcl_hook_protocol(const char *file, const char *args)
{
  const char *s;
  int ret;
  wzd_context_t * context;
  wzd_user_t * user;
  unsigned int reply_code;
  Tcl_Interp * slave = NULL;
  char * ptr;

  current_context = context = GetMyContext();
  user = GetUserByID(context->userid);
  reply_code = hook_get_current_reply_code();

  slave = _tcl_getslave(interp, context);
  if (!slave) return 0;

  {
    char buffer[5];
    snprintf(buffer,5,"%u",reply_code);
    Tcl_SetVar(slave,TCL_REPLY_CODE,buffer,TCL_GLOBAL_ONLY);
  }
  Tcl_SetVar(slave,TCL_HAS_REPLIED,"0",TCL_GLOBAL_ONLY);
  if (args)
    Tcl_SetVar(slave,TCL_ARGS,args,TCL_GLOBAL_ONLY);
  else
    Tcl_SetVar(slave,TCL_ARGS,"",TCL_GLOBAL_ONLY);
  Tcl_SetVar(slave,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);
  Tcl_SetVar(slave,TCL_WZD_RETURN,"",TCL_GLOBAL_ONLY);

  ret = Tcl_EvalFile(slave, file);

  /* XXX FIXME should we call Tcl_DecrRefCount() ? */
  current_context = NULL;
  Tcl_UnsetVar(slave,TCL_ARGS,TCL_GLOBAL_ONLY);
  Tcl_UnsetVar(slave,TCL_CURRENT_USER,TCL_GLOBAL_ONLY);
#if 0
  s = Tcl_GetVar(slave,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
#if 0
  if (!s || *s!='1') {
    if (ret != TCL_OK)
      send_message_with_args(501,context,"Error in TCL command");
    else
      send_message_with_args(200,context,"TCL command ok");
  }
#endif
#endif

  s = Tcl_GetVar(slave,TCL_WZD_RETURN,TCL_GLOBAL_ONLY);
  if (s != NULL && *s != '\0') {
    ret = strtoul(s,&ptr,0);
    if (*ptr!='\0') return 0; /** \todo log invalid return code ? */
    return ret;
  }

  return 0;
}

static void do_tcl_help(wzd_context_t * context)
{
  send_message_raw("501-\r\n",context);
  send_message_raw("501-tcl commands\r\n",context);
  send_message_raw("501- site tcl <tcl_command>\r\n",context);
  send_message_raw("501 \r\n",context);
}


/** return 0 if ok */
static int tcl_diagnose(void)
{
  int test_int;
  Tcl_Interp * test_interp, * test_slave;
  Tcl_Command test_cmd;
  Tcl_CmdInfo test_info;

  /* creation of interpreter */
  if ( (test_interp = Tcl_CreateInterp()) == NULL)
  {
    out_log(LEVEL_HIGH, "TCL error: could not create interpreter\n");
    return 1;
  }

  /* adding a command */
  test_cmd = Tcl_CreateCommand(test_interp,"ftp2sys",tcl_ftp2sys,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  if (!test_cmd)
  {
    out_log(LEVEL_HIGH, "TCL error: could not create command\n");
    out_log(LEVEL_HIGH, " error: %s\n", Tcl_GetStringResult(test_interp));
    Tcl_DeleteInterp(test_interp);
    return 2;
  }

  /* check that the command is really here */
  test_int = Tcl_GetCommandInfoFromToken(test_cmd, &test_info);
  if (!test_int)
  {
    out_log(LEVEL_HIGH, "TCL error: could not get info on command\n");
    out_log(LEVEL_HIGH, " error: %s\n", Tcl_GetStringResult(test_interp));
    Tcl_DeleteInterp(test_interp);
    return 3;
  }

  /* create a slave */
  if ( (test_slave = Tcl_CreateSlave(test_interp, "slaveName", 0)) == NULL )
  {
    out_log(LEVEL_HIGH, "TCL error: could not create slave\n");
    out_log(LEVEL_HIGH, " error: %s\n", Tcl_GetStringResult(test_interp));
    Tcl_DeleteInterp(test_interp);
    return 4;
  }

  /* create alias */
  if ( (test_int = Tcl_CreateAlias(test_slave, "ftp2sys", test_interp, "ftp2sys", 0, NULL)) != TCL_OK )
  {
    out_log(LEVEL_HIGH, "TCL error: could not create alias for slave\n");
    out_log(LEVEL_HIGH, " error: %s\n", Tcl_GetStringResult(test_interp));
    Tcl_DeleteInterp(test_slave);
    Tcl_DeleteInterp(test_interp);
    return 5;
  }

  Tcl_DeleteInterp(test_slave);
  Tcl_DeleteInterp(test_interp);

  /* run is ok */
  out_log(LEVEL_INFO, "TCL module passed self-test\n");
  return 0;
}

/***** slaves *****/
/** @brief return slave for current context.
 *
 * create the slave interpreter if needed
 *
 * \bug on user logout or timeout we need to destroy slave
 */
static Tcl_Interp * _tcl_getslave(Tcl_Interp *interp, void *context)
{
  Tcl_Interp * slave = NULL;

  char buffer[64];
  snprintf(buffer, 64, "%p", context);

  if ( (slave = Tcl_GetSlave(interp, buffer)) )
    return slave;

  if ( (slave = Tcl_CreateSlave(interp, buffer, 0)) ) {
    int ret;

    Tcl_Channel ch1, ch2; /** \bug why static ?! */
    /* replace stdout and stderr */
    ch1 = Tcl_CreateChannel(&channel_type, "wzdout", WZDOUT, TCL_WRITABLE);
    ch2 = Tcl_CreateChannel(&channel_type, "wzderr", WZDERR, TCL_WRITABLE);
    Tcl_SetStdChannel(ch1, TCL_STDOUT);
    Tcl_SetStdChannel(ch2, TCL_STDERR);

    Tcl_SetChannelOption(slave, ch1, "-buffering", "line");
    Tcl_SetChannelOption(slave, ch2, "-buffering", "line");

    Tcl_RegisterChannel(slave, ch1);
    Tcl_RegisterChannel(slave, ch2);

    ret = Tcl_CreateAlias(slave, "chgrp", interp, "chgrp", 0, NULL);
    ret = Tcl_CreateAlias(slave, "chmod", interp, "chmod", 0, NULL);
    ret = Tcl_CreateAlias(slave, "chown", interp, "chown", 0, NULL);
    ret = Tcl_CreateAlias(slave, "ftp2sys", interp, "ftp2sys", 0, NULL);
    ret = Tcl_CreateAlias(slave, "killpath", interp, "killpath", 0, NULL);
    ret = Tcl_CreateAlias(slave, "putlog", interp, "putlog", 0, NULL);
    ret = Tcl_CreateAlias(slave, "send_message", interp, "send_message", 0, NULL);
    ret = Tcl_CreateAlias(slave, "send_message_raw", interp, "send_message_raw", 0, NULL);
    ret = Tcl_CreateAlias(slave, "stat", interp, "stat", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars", interp, "vars", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars_group", interp, "vars_group", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars_shm", interp, "vars_shm", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars_user", interp, "vars_user", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vfs", interp, "vfs", 0, NULL);

    return slave;
  }

  return NULL;
}


/******* TCL functions ********/

static int tcl_chgrp(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char path[WZD_MAX_PATH+1];
  const char * groupname;

  if (argc < 3) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  groupname = argv[1];

  if ( checkpath_new(argv[2], path, current_context) ) {
    out_log(LEVEL_INFO,"tcl chgrp could not resolv path %s\n",argv[1]);
    return TCL_ERROR;
  }
  if (file_chown(path,NULL,groupname,current_context)) {
    return TCL_ERROR;
  }

  return TCL_OK;
}

static int tcl_chmod(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char path[WZD_MAX_PATH+1];
  char * endptr;
  unsigned long perms;

  if (argc < 3) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  perms = strtoul(argv[1],&endptr,8);
  if (endptr == argv[1]) {
    /** TODO try to convert from string rwxr-xr-x */
    out_log(LEVEL_INFO,"tcl chmod could not convert mode %s to octal number\n",argv[1]);
    return TCL_ERROR;
  }

  if ( checkpath_new(argv[2], path, current_context) ) {
    out_log(LEVEL_INFO,"tcl chmod could not resolv path %s\n",argv[1]);
    return TCL_ERROR;
  }
  if (_setPerm(path,NULL,NULL,NULL,NULL,perms,current_context)) {
    return TCL_ERROR;
  }

  return TCL_OK;
}

static int tcl_chown(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char path[WZD_MAX_PATH+1];
  const char * username=NULL, * groupname=NULL;
  const char * ptr;

  if (argc < 3) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  username = argv[1];

  if ((ptr = strchr(username,':'))) {
    groupname = ptr+1;
    if (ptr == username) { /* chown :group file */
      username = NULL;
    }
    else {
      *(char*)ptr = '\0'; /* yes, we're changing read-only arguments .. */
      /* from man chmod: If a colon or dot but no group name follows the user name, that user is made
       * the owner of the files and the group of the files is  changed  to  that  user’s login group.
       */
    }
  }

  if ( checkpath_new(argv[2], path, current_context) ) {
    out_log(LEVEL_INFO,"tcl chown could not resolv path %s\n",argv[1]);
    return TCL_ERROR;
  }
  if (file_chown(path,username,groupname,current_context)) {
    return TCL_ERROR;
  }

  return TCL_OK;
}

static int tcl_ftp2sys(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char *path;

  if (argc != 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  path = wzd_malloc(WZD_MAX_PATH+1);
  if ( checkpath_new(argv[1], path, current_context) ) {
    wzd_free(path);
    return TCL_ERROR;
  }
  Tcl_SetResult(interp, path, (Tcl_FreeProc *)&wzd_free);

  return TCL_OK;
}

static int tcl_killpath(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;

  if (argc < 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  if (!strcmp(argv[1],"-r") || !strcmp(argv[1],"--real")) {
    ret = killpath(argv[2], current_context);
  } else {
    char * realpath;
    realpath = malloc(WZD_MAX_PATH+1);

    if (checkpath_new(argv[2],realpath,current_context)) {
      free(realpath);
      return TCL_ERROR;
    }
    ret = killpath(realpath, current_context);
    free(realpath);
  }

  if ( ret != E_OK && ret != E_USER_NOBODY ) {
    return TCL_ERROR;
  }

  return TCL_OK;
}

static int tcl_putlog(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char *ptr;
  unsigned long level;

  if (argc < 3) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  /** \todo XXX we could format the string using argv[2,] */

  /* replace cookies ? */

  level = strtoul(argv[1],&ptr,0);
  if (*ptr!='\0') return TCL_ERROR;

  out_log( (int)level, argv[2] );

  return TCL_OK;
}

static int tcl_send_message_raw(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;

  if (argc != 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  ret = send_message_raw(argv[1],current_context);

  return TCL_OK;
}

static int tcl_send_message(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char *ptr;
  int ret;
  wzd_user_t * user = current_context ? GetUserByID(current_context->userid) : NULL;
  wzd_group_t * group = current_context ? GetGroupByID(user->groups[0]) : NULL;

  if (argc < 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  /** \todo XXX we could format the string using argv[2,] */

  ptr = malloc(4096);
  *ptr = '\0';

  cookie_parse_buffer(argv[1],user,group,current_context,ptr,4096);

  ret = send_message_raw(ptr,current_context);
  free(ptr);

  return TCL_OK;
}

static int tcl_stat(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  char * path;
  char * buffer;
  struct wzd_file_t * file;

  if (argc < 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  path = wzd_malloc(WZD_MAX_PATH+1);
  /* use checkpath, we don't want to resolve links */
  if (!strcmp(argv[1],"-r") || !strcmp(argv[1],"--real")) {
    /* ex: vfs read -r c:\real */
    if (argc < 3) { wzd_free(path); return TCL_ERROR; }
    strncpy(path, argv[2], WZD_MAX_PATH);
  } else {
    if ( checkpath(argv[1], path, current_context) ) {
      wzd_free(path);
      return TCL_ERROR;
    }
  }
  REMOVE_TRAILING_SLASH(path);
  file = file_stat(path, current_context);
  wzd_free(path);
  buffer = wzd_malloc(256);

  if (file == (struct wzd_file_t *)-1) {
    buffer[0] = '\0';
  } else if (file) {
    snprintf(buffer,256,"%s/%s/%lo", file->owner, file->group, file->permissions);
  } else {
    /* we know nothing about this file */
    snprintf(buffer,256,"%s/%s/%o", "unknown", "unknown", 0755);
  }

  if (file && file != (struct wzd_file_t*)-1)
    free_file_recursive(file);

  Tcl_SetResult(interp, buffer, (Tcl_FreeProc *)&wzd_free);

  return TCL_OK;
}

static int tcl_vars(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;
  char *buffer;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  Tcl_ResetResult(interp);

  if (!strcmp(argv[1],"get")) {
    buffer = wzd_malloc(1024);

    ret = vars_get(argv[2],buffer,1024,getlib_mainConfig());
    if (!ret)
      Tcl_SetResult(interp, buffer, (Tcl_FreeProc *)&wzd_free);
    else
    {
      wzd_free(buffer);
      return TCL_ERROR;
    }
  } else if (!strcmp(argv[1],"set")) {
    ret = vars_set(argv[2],(void*)argv[3],1024,getlib_mainConfig());
    return (ret)?TCL_ERROR:TCL_OK;
  }

  return TCL_OK;
}

static int tcl_vars_group(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;
  char *buffer;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  Tcl_ResetResult(interp);

  if (!strcmp(argv[1],"get")) {
    buffer = wzd_malloc(1024);

    ret = vars_group_get(argv[2],argv[3],buffer,1024,getlib_mainConfig());
    if (!ret)
      Tcl_SetResult(interp, buffer, (Tcl_FreeProc *)&wzd_free);
    else
    {
      wzd_free(buffer);
      return TCL_ERROR;
    }
  } else if (!strcmp(argv[1],"set")) {
    ret = vars_group_set(argv[2],argv[3],(void*)argv[4],1024,getlib_mainConfig());
    return (ret)?TCL_ERROR:TCL_OK;
  } else if (!strcmp(argv[1],"new")) { /* new group creation */
    ret = vars_group_new(argv[2],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
#if 0
  } else if (!strcmp(argv[1],"addip")) { /* add new ip */
    ret = vars_group_addip(argv[2],argv[3],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
  } else if (!strcmp(argv[1],"delip")) { /* remove ip */
    ret = vars_group_delip(argv[2],argv[3],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
#endif
  }

  return TCL_ERROR;
}

static int tcl_vars_shm(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;
  char *buffer;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  Tcl_ResetResult(interp);

  if (!strcmp(argv[1],"get")) {
    buffer = wzd_malloc(1024);

    ret = vars_shm_get(argv[2], buffer, 1024, getlib_mainConfig());
    if (!ret)
      Tcl_SetResult(interp, buffer, (Tcl_FreeProc *)&wzd_free);
    else
    {
      Tcl_SetResult(interp, "0", (Tcl_FreeProc *)NULL);
      wzd_free(buffer);
      return TCL_OK;
    }
  } else if (!strcmp(argv[1],"set")) {
    ret = vars_shm_set(argv[2], (void*)argv[3], strlen(argv[3])+1, getlib_mainConfig());
    return TCL_OK;
  }

  return TCL_OK;
}

static int tcl_vars_user(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;
  char *buffer;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  Tcl_ResetResult(interp);

  if (!strcmp(argv[1],"get")) {
    buffer = wzd_malloc(1024);

    ret = vars_user_get(argv[2],argv[3],buffer,1024,getlib_mainConfig());
    if (!ret)
      Tcl_SetResult(interp, buffer, (Tcl_FreeProc *)&wzd_free);
    else
    {
      wzd_free(buffer);
      return TCL_ERROR;
    }
  } else if (!strcmp(argv[1],"set")) {
    ret = vars_user_set(argv[2],argv[3],(void*)argv[4],1024,getlib_mainConfig());
    return (ret)?TCL_ERROR:TCL_OK;
  } else if (!strcmp(argv[1],"new")) { /* new user creation */
    ret = vars_user_new(argv[2],argv[3],argv[4],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
  } else if (!strcmp(argv[1],"addip")) { /* add new ip */
    ret = vars_user_addip(argv[2],argv[3],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
  } else if (!strcmp(argv[1],"delip")) { /* remove ip */
    ret = vars_user_delip(argv[2],argv[3],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
  }

  return TCL_OK;
}

static int tcl_vfs(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;
  char buffer_real[WZD_MAX_PATH+1];
  char buffer_link[WZD_MAX_PATH+1];
  int pos1, pos2;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  /* XXX all following commands wants an absolute path */
  if (!strcmp(argv[1],"mkdir")) {
    pos1 = 2;
    if (!strcmp(argv[pos1],"-r") || !strcmp(argv[pos1],"--real")) {
      /* ex: vfs link mkdir -r c:\real */
      pos1++;
      if (argc <= pos1) return TCL_ERROR;
      strncpy(buffer_real, argv[pos1], sizeof(buffer_real));
    } else {
      if (checkpath_new(argv[pos1],buffer_real,current_context) != E_FILE_NOEXIST)
        return TCL_ERROR;
    }
    ret = file_mkdir(buffer_real, 0755, current_context); /** \todo remove hardcoded umask */
  }
  else if (!strcmp(argv[1],"rmdir")) {
    pos1 = 2;
    if (!strcmp(argv[pos1],"-r") || !strcmp(argv[pos1],"--real")) {
      /* ex: vfs link mkdir -r c:\real */
      pos1++;
      if (argc <= pos1) return TCL_ERROR;
      strncpy(buffer_real, argv[pos1], sizeof(buffer_real));
    } else {
      if (checkpath_new(argv[pos1],buffer_real,current_context))
        return TCL_ERROR;
    }
    ret = file_rmdir(buffer_real,current_context);
  }
  else if (!strcmp(argv[1],"read")) {
    return tcl_stat(data, interp, argc-1, argv+1); /* pass through tcl_stat */
  }
  else if (!strcmp(argv[1],"link")) {
    /* TODO move this code to symlink_create ? */
    if (argc <= 3) return TCL_ERROR;
    if (!strcmp(argv[2],"create")) {
      pos1 = 3; /* position of existing dir */
      pos2 = 4; /* position of link name */
      if (argc <= 4) return TCL_ERROR;
      if (!strcmp(argv[pos1],"-r") || !strcmp(argv[pos1],"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos1++; pos2++;
        if (argc <= pos2) return TCL_ERROR;
        strncpy(buffer_real, argv[pos1], sizeof(buffer_real));
      } else {
        if (checkpath_new(argv[pos1],buffer_real,current_context) != E_FILE_NOEXIST)
          return TCL_ERROR;
      }
      if (!strcmp(argv[pos2],"-r") || !strcmp(argv[pos2],"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos2++;
        if (argc <= pos2) return TCL_ERROR;
        strncpy(buffer_link, argv[pos2], sizeof(buffer_link));
      } else {
        if (checkpath_new(argv[pos2],buffer_link,current_context) != E_FILE_NOEXIST)
          return TCL_ERROR;
      }

      REMOVE_TRAILING_SLASH(buffer_link);
      REMOVE_TRAILING_SLASH(buffer_real);
      ret = symlink_create(buffer_real,buffer_link);
    }
    else if (!strcmp(argv[2],"remove")) {
      pos2 = 3;
      /* we need to convert arg to the link name, _without_ converting the last
       * component (the link name itself), or the remove will fail
       */
      if (!strcmp(argv[pos2],"-r") || !strcmp(argv[pos2],"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos2++;
        if (argc <= pos2) return TCL_ERROR;
        strncpy(buffer_link, argv[pos2], sizeof(buffer_link));
      } else {
        if (checkpath(argv[pos2],buffer_link,current_context))
          return TCL_ERROR;
      }
      ret = symlink_remove(buffer_link);
    }
    else
      ret = TCL_ERROR;
  }
  else
    ret = TCL_ERROR;

  return (ret)?TCL_ERROR:TCL_OK;
}

/******* I/O Channel ********/

static int channel_close(ClientData instance, Tcl_Interp *interp)
{
  int err=0;

  /* currently does nothing */
  if (instance != WZDOUT && instance != WZDERR)
  {
    Tcl_SetErrno(EBADF);
    err = EBADF;
  }
  return err;
}

static int channel_input(ClientData instance, char *buf, int bufsiz, int *errptr)
{
  /* input is currently not supported */

  Tcl_SetErrno(EINVAL);
  if (errptr)
    *errptr = EINVAL;
  return -1;
}

static int channel_output(ClientData instance, const char *buf, int bufsiz, int *errptr)
{
  char * str;
  int result;

  /* buf is not guaranteed to be 0-terminated */
  str = malloc (bufsiz+1);
  if (!str) {
    Tcl_SetErrno(ENOMEM);
    if (errptr) *errptr = ENOMEM;
    return -1;
  }
  strncpy(str, buf, bufsiz);
  str[bufsiz] = '\0';

  result = bufsiz;
  if (instance == WZDOUT)
    out_err(LEVEL_INFO,"tcl OUT: [%s]\n", str);
  else if (instance == WZDERR) {
    out_err(LEVEL_HIGH,"tcl ERR: [%s]\n", str);
    if (tcl_fd_errlog >= 0)
      write(tcl_fd_errlog, str, bufsiz);
  }
  else {
    Tcl_SetErrno(EBADF);
    if (errptr) *errptr = EBADF;
    result = -1;
  }

  free(str);
  return result;
}

static void channel_watch(ClientData instance, int mask)
{
  Tcl_SetErrno(EINVAL);
}

static int channel_gethandle(ClientData instance, int direction, ClientData *handleptr)
{
  Tcl_SetErrno(EINVAL);
  return EINVAL;
}

