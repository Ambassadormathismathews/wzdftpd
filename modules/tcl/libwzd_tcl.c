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
#include "wzd_file.h" /* file_mkdir */
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

/***** PROTO HOOKS *****/
static int tcl_hook_protocol(const char *file, const char *args);

/***** TCL commands ****/
static int tcl_send_message(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_send_message_raw(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vars_user(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);
static int tcl_vfs(ClientData data, Tcl_Interp *interp, int argc, const char *argv[]);


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
  Tcl_CreateCommand(interp,"send_message",tcl_send_message,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"send_message_raw",tcl_send_message_raw,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars",tcl_vars,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vars_user",tcl_vars_user,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  Tcl_CreateCommand(interp,"vfs",tcl_vfs,(ClientData)NULL,(Tcl_CmdDeleteProc*)NULL);
  hook_add(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&tcl_hook_site);
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
      const char *s;
      wzd_user_t * user;
      int ret;

      current_context = context;
      user = GetUserByID(context->userid);
      Tcl_SetVar(interp,TCL_HAS_REPLIED,"0",TCL_GLOBAL_ONLY);
      Tcl_SetVar(interp,TCL_REPLY_CODE,"200",TCL_GLOBAL_ONLY);
      Tcl_SetVar(interp,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);
      TempObj = Tcl_NewStringObj(args,-1);
      ret = Tcl_EvalObj(interp, TempObj);
      /* XXX FIXME should we call Tcl_DecrRefCount() ? */
      current_context = NULL;
      s = Tcl_GetVar(interp,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
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

static int tcl_hook_protocol(const char *file, const char *args)
{
  const char *s;
  int ret;
  wzd_context_t * context;
  wzd_user_t * user;
  unsigned int reply_code;

  current_context = context = GetMyContext();
  user = GetUserByID(context->userid);
  reply_code = hook_get_current_reply_code();
  {
    char buffer[5];
    snprintf(buffer,5,"%u",reply_code);
    Tcl_SetVar(interp,TCL_REPLY_CODE,buffer,TCL_GLOBAL_ONLY);
  }
  Tcl_SetVar(interp,TCL_HAS_REPLIED,"0",TCL_GLOBAL_ONLY);
  Tcl_SetVar(interp,TCL_ARGS,args,TCL_GLOBAL_ONLY);
  Tcl_SetVar(interp,TCL_CURRENT_USER,user->username,TCL_GLOBAL_ONLY);

  ret = Tcl_EvalFile(interp, file);

  /* XXX FIXME should we call Tcl_DecrRefCount() ? */
  current_context = NULL;
  Tcl_UnsetVar(interp,TCL_ARGS,TCL_GLOBAL_ONLY);
  Tcl_UnsetVar(interp,TCL_CURRENT_USER,TCL_GLOBAL_ONLY);
  s = Tcl_GetVar(interp,TCL_HAS_REPLIED,TCL_GLOBAL_ONLY);
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


/******* TCL functions ********/
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
  unsigned int length;

  if (argc != 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  /** \todo XXX we could format the string using argv[2,] */

  length = strlen(argv[1]);
  ptr = malloc(length+4);
  snprintf(ptr,length+4," %s\r\n",argv[1]);

  ret = send_message_raw(ptr,current_context);

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
  }

  return TCL_OK;
}

static int tcl_vfs(ClientData data, Tcl_Interp *interp, int argc, const char *argv[])
{
  int ret;

  if (argc <= 2) return TCL_ERROR;
  if (!current_context) return TCL_ERROR;

  /* XXX all following commands wants an absolute path */
  if (!strcmp(argv[1],"mkdir")) {
    ret = file_mkdir(argv[2],0755,current_context);
  }
  else if (!strcmp(argv[1],"rmdir")) {
    ret = file_rmdir(argv[2],current_context);
  }
  else if (!strcmp(argv[1],"link")) {
    if (argc <= 3) return TCL_ERROR;
    if (!strcmp(argv[2],"create")) {
      ret = symlink_create(argv[3],argv[4]);
    }
    else if (!strcmp(argv[2],"remove")) {
      ret = symlink_remove(argv[3]);
    }
    else
      ret = TCL_ERROR;
  }
  else
    ret = TCL_ERROR;
  
  return (ret)?TCL_ERROR:TCL_OK;
}
