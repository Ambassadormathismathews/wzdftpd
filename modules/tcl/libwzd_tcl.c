/* vi:ai:et:ts=8 sw=2
 */
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

/* XXX FIXME
 * IMPORTANT NOTES: this module does not like unloading,
 * it provokes a segfault at thread exit
 * This seems to be a problem between threads and shared libs.
 */
/* XXX FIXME
 * the following code is NOT reentrant at all
 * I should use locks and/or use interpreter slaves
 */

/* README
 *
 * The tcl interpreter is shared between all clients, it means all data
 * created by one user can be accessed by another.
 * This can cause some security problems, so be carefull to who you give TCL access.
 *
 * In the future, we'll try to solve this problem managing several Tcl_Interp vars ...
 */

/* URL: http://aspn.activestate.com/ASPN/docs/ActiveTcl/tcl/tcl_13_contents.htm
 */

#include <stdio.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <direct.h>
#include <io.h>

#include "../../visual/gnu_regex_dist/regex.h"
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
#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_libmain.h"
#include "wzd_messages.h"
#include "wzd_file.h" /* file_mkdir, file_stat */
#include "wzd_vfs.h" /* checkpath_new */
#include "wzd_mod.h" /* essential to define WZD_MODULE_INIT */
#include "wzd_vars.h" /* needed to access variables */

#include "wzd_debug.h"

/***** Private vars ****/
static Tcl_Interp * interp=NULL;
static wzd_context_t * current_context=NULL;

#define TCL_ARGS        "wzd_args"
#define TCL_CURRENT_USER "wzd_current_user"
#define TCL_REPLY_CODE  "wzd_reply_code"
#define TCL_HAS_REPLIED "wzd_replied"

/***** Private fcts ****/
static void do_tcl_help(wzd_context_t * context);

/***** EVENT HOOKS *****/
static int tcl_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args);
static int tcl_hook_logout(unsigned long event_id, wzd_context_t *context, const char *username);

/***** PROTO HOOKS *****/
static int tcl_hook_protocol(const char *file, const char *args);

/***** TCL commands ****/
static int tcl_ftp2sys(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_putlog(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_send_message(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_send_message_raw(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_stat(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_group(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_user(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vfs(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);

/***** slaves *****/
static Tcl_Interp * _tcl_getslave(Tcl_Interp *interp, void *context);


/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
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
  interp = Tcl_CreateInterp();
  if (!interp) {
    out_log(LEVEL_HIGH,"TCL could not create interpreter\n");
    return -1;
  }
  Tcl_CreateCommand(interp,"ftp2sys",tcl_ftp2sys,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"putlog",tcl_putlog,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"send_message",tcl_send_message,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"send_message_raw",tcl_send_message_raw,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"stat",tcl_stat,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars",tcl_vars,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_group",tcl_vars_group,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_user",tcl_vars_user,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vfs",tcl_vfs,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  hook_add(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&tcl_hook_site);
  hook_add(&getlib_mainConfig()->hook,EVENT_LOGOUT,(void_fct)&tcl_hook_logout);
  hook_add_protocol("tcl:",4,&tcl_hook_protocol);
  out_log(LEVEL_INFO,"TCL module loaded\n");
  return 0;
}

void WZD_MODULE_CLOSE(void)
{
  Tcl_DeleteInterp(interp);
  interp = NULL;
/*  Tcl_Exit(0);*/
  out_log(LEVEL_INFO,"TCL module unloaded\n");
}



static int tcl_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args)
{
  if (strcasecmp(token,"tcl")==0) {
    if (!args || strlen(args)==0) { do_tcl_help(context); return 0; }
    {
      Tcl_Obj * TempObj;
      Tcl_Interp * slave = NULL;
      const char *s;
      wzd_user_t * user;
      int ret;

      slave = _tcl_getslave(interp, context);
      if (!slave) return 0;

      current_context = context;
      user = GetUserByID(context->userid);
      Tcl_SetVar(slave,TCL_HAS_REPLIED,"0",TCL_GLOBAL_ONLY);
      Tcl_SetVar(slave,TCL_REPLY_CODE,"200",TCL_GLOBAL_ONLY);
      Tcl_SetVar(slave,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);
      TempObj = Tcl_NewStringObj(args,-1);
      ret = Tcl_EvalObj(slave, TempObj);
      /* XXX FIXME should we call Tcl_DecrRefCount() ? */
      current_context = NULL;
      s = Tcl_GetVar(slave,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
      if (!s || *s!='1') {
        if (ret != TCL_OK)
          send_message_with_args(501,context,"Error in TCL command");
        else
          send_message_with_args(200,context,"TCL command ok");
      }
    }
  }
  return 0;
}

static int tcl_hook_logout(unsigned long event_id, wzd_context_t * context, const char *username)
{
  Tcl_Interp * slave = NULL;

  char buffer[64];
  snprintf(buffer, 64, "%p", context);

  if ( (slave = Tcl_GetSlave(interp, buffer)) )
  {
    Tcl_DeleteInterp(slave);
  }

  return 0;
}

static int tcl_hook_protocol(const char *file, const char *args)
{
  const char *s;
  int ret;
  wzd_context_t * context;
  wzd_user_t * user;
  unsigned int reply_code;
  Tcl_Interp * slave = NULL;

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
  Tcl_SetVar(slave,TCL_ARGS,args,TCL_GLOBAL_ONLY);
  Tcl_SetVar(slave,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);

  ret = Tcl_EvalFile(slave, file);

  /* XXX FIXME should we call Tcl_DecrRefCount() ? */
  current_context = NULL;
  Tcl_UnsetVar(slave,TCL_ARGS,TCL_GLOBAL_ONLY);
  Tcl_UnsetVar(slave,TCL_CURRENT_USER,TCL_GLOBAL_ONLY);
  s = Tcl_GetVar(slave,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
#if 0
  if (!s || *s!='1') {
    if (ret != TCL_OK)
      send_message_with_args(501,context,"Error in TCL command");
    else
      send_message_with_args(200,context,"TCL command ok");
  }
#endif

  return 0;
}

static void do_tcl_help(wzd_context_t * context)
{
  send_message_raw("501-\r\n",context);
  send_message_raw("501-tcl commands\r\n",context);
  send_message_raw("501- site tcl <tcl_command>\r\n",context);
  send_message_raw("501 \r\n",context);
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
    ret = Tcl_CreateAlias(slave, "ftp2sys", interp, "ftp2sys", 0, NULL);
    ret = Tcl_CreateAlias(slave, "putlog", interp, "putlog", 0, NULL);
    ret = Tcl_CreateAlias(slave, "send_message", interp, "send_message", 0, NULL);
    ret = Tcl_CreateAlias(slave, "send_message_raw", interp, "send_message_raw", 0, NULL);
    ret = Tcl_CreateAlias(slave, "stat", interp, "stat", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars", interp, "vars", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars_group", interp, "vars_group", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vars_user", interp, "vars_user", 0, NULL);
    ret = Tcl_CreateAlias(slave, "vfs", interp, "vfs", 0, NULL);

    return slave;
  }

  return NULL;
}


/******* TCL functions ********/

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

  cookie_parse_buffer(argv[1],user,group,current_context,ptr,4096);

  ret = send_message_raw(ptr,current_context);

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
    if (argc < 3) return TCL_ERROR;
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
    snprintf(buffer,256,"%s/%s/%o", file->owner, file->group, file->permissions);
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
#if 0
  } else if (!strcmp(argv[1],"new")) { /* new user creation */
    ret = vars_group_new(argv[2],argv[3],argv[4],getlib_mainConfig());
    /** \todo handle return */
    return (ret)?TCL_ERROR:TCL_OK;
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
      if (checkpath_new(argv[pos1],buffer_real,current_context) != E_FILE_NOEXIST)
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
      /* we need to convert arg to the link name, _without_ converting the last
       * component (the link name itself), or the remove will fail
       */
      if (checkpath(argv[3],buffer_link,current_context)) return TCL_ERROR;
      ret = symlink_remove(buffer_link);
    }
    else
      ret = TCL_ERROR;
  }
  else
    ret = TCL_ERROR;
  
  return (ret)?TCL_ERROR:TCL_OK;
}
