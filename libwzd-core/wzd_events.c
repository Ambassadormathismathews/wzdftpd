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

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <wchar.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/wait.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_cache.h"
#include "wzd_events.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

/** \file wzd_events.c
 * \brief Connect events to callback functions
 *
 * A callback is implemented as a closure: when defining the callback, a list
 * of additional parameters is specified.
 * As we do not have a portable implementation for closures, we use a linked
 * list for parameters.
 *
 * Ideas:
 *  - the implementation could use a priority queue, so the users can specify
 *  a priority when adding a connection.
 *  - add a flag PARALLEL / SEQUENTIAL to specify if the job can be run in
 *  another thread or not
 *
 * \addtogroup libwzd_core
 * @{
 */


static void _event_free(wzd_event_t * event);
static event_reply_t _event_print_file(const char *filename, wzd_context_t * context);

static event_reply_t _event_exec_shell(const char * commandline, wzd_context_t * context);

void _cleanup_shell_command(char * buffer, size_t length);

int my_spawn_nowait(const char * command);

void event_mgr_init(wzd_event_manager_t * mgr)
{
  WZD_ASSERT_VOID( mgr != NULL);

  mgr->event_list = wzd_malloc( sizeof(List) );
  list_init(mgr->event_list, (void (*)(void*))_event_free);
}

void event_mgr_free(wzd_event_manager_t * mgr)
{
  WZD_ASSERT_VOID( mgr != NULL);

  list_destroy(mgr->event_list);
  wzd_free(mgr->event_list);

  memset(mgr, 0, sizeof(wzd_event_manager_t));
}

/*** these are candidate prototypes ... work in progress */

int event_connect_function(wzd_event_manager_t * mgr, u32_t event_id, event_function_t callback, wzd_string_t * params)
{
  wzd_event_t * event;

  WZD_ASSERT( mgr != NULL );

  event = wzd_malloc(sizeof(wzd_event_t));
  event->id = event_id;
  event->callback = callback;
  event->external_command = NULL;
  event->params = str_dup(params);

  list_ins_next(mgr->event_list, list_tail(mgr->event_list), event);

  return 0;
}

int event_connect_external(wzd_event_manager_t * mgr, u32_t event_id, wzd_string_t * external_command, wzd_string_t * params)
{
  wzd_event_t * event;

  WZD_ASSERT( mgr != NULL );

  event = wzd_malloc(sizeof(wzd_event_t));
  event->id = event_id;
  event->callback = NULL;
  event->external_command = str_dup(external_command);
  event->params = str_dup(params);

  list_ins_next(mgr->event_list, list_tail(mgr->event_list), event);

  return 0;
}

int event_send(wzd_event_manager_t * mgr, u32_t event_id, unsigned int reply_code, wzd_string_t * params, wzd_context_t * context)
{
  ListElmt * elmnt;
  wzd_event_t * event;
  int ret;
  char fixed_args[4096];
  char buffer_args[4096];
  char * args;
  size_t length;
  wzd_user_t * user = GetUserByID(context->userid);
  wzd_group_t * group = NULL;

  WZD_ASSERT( mgr != NULL);

  if (!user)
    return -1;

  if (user->group_num > 0) group = GetGroupByID(user->groups[0]);

#ifdef WZD_DBG_EVENT
  out_log(LEVEL_FLOOD,"DEBUG Sending event 0x%lx\n",event_id);
#endif

  /* prepare arguments */
  /*   add command line args to permanent args */
  buffer_args[0] = '\0';
  if (params) {
    cookie_parse_buffer(str_tochar(params), user, group, context, buffer_args, sizeof(buffer_args));
    chop(buffer_args);
  }

  ret = EVENT_OK;

  for (elmnt=list_head(mgr->event_list); elmnt; elmnt=list_next(elmnt)) {
    event = list_data(elmnt);
    WZD_ASSERT( event != NULL );

    if ( (event->id & event_id) ) {

      args = fixed_args; args[0] = '\0';
      length = sizeof(fixed_args);

      if (event->external_command) {
        wzd_strncpy(args, str_tochar(event->external_command), length);
        strlcat(args," ",length);
        args += strlen(args);
        length -= strlen(args);
      }

      if (event->params) {
        /** \todo check *only* arguments of command ! */
        cookie_parse_buffer(str_tochar(event->params), user, group, context, args, length);
        chop(args);

        if (params) {
          strlcat(fixed_args," ",sizeof(fixed_args));
          strlcat(fixed_args,buffer_args,sizeof(fixed_args));
        }
      } else {
        if (params) {
          if (fixed_args[0] != '\0')
            strlcat(fixed_args," ",sizeof(fixed_args));
          strlcat(fixed_args,buffer_args,sizeof(fixed_args));
        }
      }
      args = fixed_args;

      if (event->callback) {
        ret = (event->callback)(args);
      } else {
        ret = event_exec(args,context);
      }
      if (ret != EVENT_OK) return ret;
    }
  }

  /* return result from last command */
  return ret;
}



static void _event_free(wzd_event_t * event)
{
  str_deallocate(event->external_command);
  str_deallocate(event->params);
  wzd_free(event);
}

event_reply_t event_exec(const char * commandline, wzd_context_t * context)
{
  int ret;
  char buffer[1024];
  protocol_handler_t * proto;

  wzd_strncpy(buffer,commandline,sizeof(buffer));

  if (buffer[0] == '!') { /* print the corresponding file */
    ret = _event_print_file(buffer+1, context);
  } else {
    /* check for perl: like protocols */
    proto = hook_check_protocol(buffer);

    if (proto) {
      char * command, * args;
      /* skip signature */
      command = buffer + proto->siglen;
      /* split command and arguments */
      if (command[0] == '"' || command[0] == '\'') {
        args = strchr(command+1,command[0]);
        if (!args) { /* unbalanced quotes */
          return EVENT_ERROR;
        }
        command++;
        *args++ = '\0';
        while (*args && (*args == ' ' || *args == '\t'))
          args++;
      } else {
        command = strtok_r(command," \t",&args);
      }
      ret = (*proto->handler)(command,args);
    } else {
      /* call external command */
      _cleanup_shell_command(buffer, sizeof(buffer));
      out_log(LEVEL_INFO,"INFO calling external command [%s]\n",buffer);
      ret = _event_exec_shell(buffer,context);
      if (ret != 0) {
        reply_set_code(context,501);
        reply_push(context,"Error during external command");
      }
    }
  }


  return ret;
}

static event_reply_t _event_print_file(const char *filename, wzd_context_t * context)
{
  wzd_cache_t * fp;
  char * file_buffer;
  unsigned int size, filesize;
  u64_t sz64;
  wzd_user_t * user = GetUserByID(context->userid);
  wzd_group_t * group = GetGroupByID(user->groups[0]);

  fp = wzd_cache_open(filename,O_RDONLY,0644);
  if (!fp) {
    send_message_raw("200 Inexistant file\r\n",context);
    return EVENT_ERROR;
  }
  sz64 = wzd_cache_getsize(fp);
  if (sz64 > INT_MAX) {
    out_log(LEVEL_HIGH,"%s:%d couldn't allocate %" PRIu64 "bytes for file %s\n",__FILE__,__LINE__,sz64,filename);
    wzd_cache_close(fp);
    send_message_raw("200 Internal error\r\n",context);
    return EVENT_ERROR;
  }
  filesize = (unsigned int)sz64;
  file_buffer = malloc(filesize+1);
  if ( (size=(unsigned int)wzd_cache_read(fp,file_buffer,filesize))!=filesize )
  {
    out_log(LEVEL_HIGH,"Could not read file %s read %u instead of %u (%s:%d)\n",filename,size,filesize,__FILE__,__LINE__);
    free(file_buffer);
    wzd_cache_close(fp);
    send_message_raw("200 Internal error\r\n",context);
    return EVENT_ERROR;
  }
  file_buffer[filesize]='\0';

  send_message_raw("200-\r\n",context);
  cookie_parse_buffer(file_buffer,user,group,context,NULL,0);
  send_message_raw("200 Command OK\r\n",context);

  wzd_cache_close(fp);

  free(file_buffer);

  return EVENT_OK;
}

#ifndef WIN32
static event_reply_t _event_exec_shell(const char * commandline, wzd_context_t * context)
{
#if 0
  wzd_string_t * str, * commandname;

  str = STR(commandline);
  commandname = str_read_token(str);

  if (str && commandname) {
    out_log(LEVEL_FLOOD,"DEBUG: will exec [%s] [%s]\n",str_tochar(commandname),str_tochar(str));
  }


  str_deallocate(commandname);
  str_deallocate(str);
  return 0;
#endif

  wzd_popen_t * p;
  FILE * file;
  char buffer[1024];
  int ret;
  
  p = wzd_popen(commandline);
  if (!p) {
/*    out_log(LEVEL_HIGH,"Hook '%s': unable to popen\n",hook->external_command);*/
    out_log(LEVEL_INFO,"Failed command: '%s'\n",commandline);
    return EVENT_ERROR;
  }
  file = fdopen(p->fdr,"r");

  if (file != NULL)
  {
    while (fgets(buffer,sizeof(buffer)-1,file) != NULL)
    {
      send_message_raw(buffer,context);
    }
    fclose(file);
  }
  else
  {
      send_message_raw("fopen failed in exec_shell\r\n",context);
      snprintf(buffer, sizeof(buffer)-1, "fopen returned errno=%d\r\n", errno);
      send_message_raw(buffer,context);
  }

  ret = wzd_pclose(p);

  return ret;
}

#else /* WIN32 */

static event_reply_t _event_exec_shell(const char * commandline, wzd_context_t * context)
{
  FILE * file;
  char buffer[WZD_BUFFER_LEN];
  char clean_command[WZD_MAX_PATH];
  int ret = EVENT_OK;

  wzd_strncpy(clean_command,commandline,WZD_MAX_PATH);
  _cleanup_shell_command(clean_command,WZD_MAX_PATH);

  file = _popen(clean_command,"r");
  if (file == NULL) {
/*    out_log(LEVEL_HIGH,"Hook '%s': unable to popen\n",hook->external_command);*/
    out_log(LEVEL_INFO,"Failed command: '%s'\n",clean_command);
    return EVENT_ERROR;
  }
  while (fgets(buffer,sizeof(buffer)-1,file) != NULL)
  {
    send_message_raw(buffer,context);
  }
  ret = _pclose(file);

  return ret;
}

#endif /* WIN32 */

/** \brief Parse string and escape characters
 *
 * \note length should *not* be the length of the string, but the allocated
 * size (or it will be truncated)
 */
void _cleanup_shell_command(char * buffer, size_t length)
{
#ifndef WIN32
  const char * specials = "$|;!`()'#,:*?{}[]&<>~";
#else
  const char * specials = "$|;!`()'#,*?{}[]&<>~";
#endif
  size_t i,j;
  char * buf2;

  buf2 = wzd_malloc(length+1);

  for (i=0,j=0; buffer[i]!='\0' && i<length && j<length; i++,j++) {
    if (strchr(specials,buffer[i]) != NULL) {
      if (j+1 >= length) break;
      buf2[j++] = '\\';
    }
    buf2[j] = buffer[i];
  }
  buf2[j] = '\0';

  wzd_strncpy(buffer,buf2,length);
  wzd_free(buf2);
}

#ifndef WIN32

wzd_popen_t * wzd_popen(const char * command)
{
  int p[2]; /* pipe contains: read,write */
  int child_pid;
  wzd_popen_t * ret;

  if (pipe(p)<0) {
    fprintf(stderr,"error during pipe: %d\n",errno);
    return NULL;
  }

  child_pid = fork();

  if (child_pid) { /* parent */

    /* we won't write to the pipe */
    close(p[1]);

    ret = wzd_malloc(sizeof(wzd_popen_t));

    ret->child_pid = child_pid;
    ret->fdr = p[0];
    FD_REGISTER(ret->fdr,"Child process (popen)");

  } else { /* child */

    /* close our stdin, stdout and stderr */
    close(0);
    close(1);
    close(2);

    /* and replace it by the pipe */
    dup2(p[1],1);
    close(p[1]);

    /* we won't read from the pipe */
    close(p[0]);

    if (my_spawn_nowait(command)<0) {
      exit (-1);
    }
  }

  return ret;
}

event_reply_t wzd_pclose(wzd_popen_t * p)
{
  int pid;
  int status;
  int retcode;

  close(p->fdr);
  FD_UNREGISTER(p->fdr,"Child process (popen)");

  pid = waitpid(p->child_pid, &status, 0);

  if (WIFEXITED(status)) {
    out_log(LEVEL_FLOOD,"DEBUG spawned process %d exited with status %d\n",p->child_pid,WEXITSTATUS(status));
    retcode = WEXITSTATUS(status);
  } else {
    if (WIFSIGNALED(status)) {
      out_log(LEVEL_NORMAL,"INFO spawned process %d exited abnormally by signal %d\n",p->child_pid,WTERMSIG(status));
    } else {
      out_log(LEVEL_NORMAL,"INFO spawned process %d exited abnormally\n",p->child_pid);
    }
    retcode = EVENT_ERROR;
  }

  wzd_free(p);

  return retcode;
}

static int _argv_chr_is_escape(const char *string, int pos)
{
  if (pos > 0) if (string[pos - 1] == '\\') return 1;
  return 0;
}

static void _argv_init(char ***argv, int *argc)
{
  *argc = 0;
  *argv = malloc(sizeof(char *));
  *argv[*argc] = NULL;
}

static void _argv_add(char ***argv, int *argc, char *str)
{
  *argv = realloc(*argv, (*argc + 2) * sizeof(char *));
  (*argv)[(*argc)++] = str;
  (*argv)[*argc] = NULL;
}

static void _argv_add_char(char **string, const char* str, int pos)
{
  int len=0;

  /** \fixme XXX work needed: do not realloc for each character, allocate buffer big
   * enough (size can not be greater to WZD_MAX_PATH)
   */

  /* first call, first alloc */
  if (*string == NULL) {
    *string=malloc(sizeof(char));
    (*string)[0] = '\0';
  }
  len = strlen(*string);
  
  /* check if '\' is escape */
  if (! _argv_chr_is_escape(str, pos) && str[pos] == '\\')
    return;

  /* check if '\' is escape by an already escape '\' */
  if ( _argv_chr_is_escape(str, pos-1) && _argv_chr_is_escape(str, pos) &&
       str[pos] == '\\')
    return;

  /* realloc && add */
  *string = realloc(*string, (len + 2) * sizeof(char));
  (*string)[len] = str[pos];
  (*string)[len+1] = '\0';
}

static void _argv_parse(const char *command, char ***argv)
{
  int i, argc;

  char *token=NULL;
  int found_end=0;
  int found_quote=0;

  if (! command) return;
 
  /* init argv */
  _argv_init(argv, &argc);

  for(i=0; command[i] != '\0'; i++) {
    found_end=0;

    /* check for quote */
    if ( ! _argv_chr_is_escape(command, i) && command[i] == '"') {
      if ( ! found_quote) {
        found_quote = 1;
        continue; /* ignore the quote */
      }
      found_end=1;
      found_quote=0;
    }

    /* check for space or tabulation */
    if ((command[i] == '\t' || command[i] == ' ')) {
      if ( token && ! found_quote ) {
        found_end=1;
      }
      if ( ! token && ! found_quote ) {
        continue; /* ignore space or tabulation */
      }
    }
    
    /* check if argument is finish && add it to argv */
    if (found_end) {
      _argv_add(argv, &argc, token);
      token=NULL;
      continue; /* ignore delim */
    }
    
    /* add current char to token */
    _argv_add_char(&token, command, i);
  }
  /* check if token is not empty => add to argv */
  if (token) _argv_add(argv, &argc, token);
}

int my_spawn_nowait(const char * command)
{
  char ** argv = NULL;
  char ** envp;
  int ret = -1;

  /* parse argv */
  _argv_parse(command, &argv);

  /** \todo get env ? Use env to store reply code */
  envp = NULL;

  if (argv[0]) {
    ret = execve(argv[0],argv,envp);
  }

  return ret;
}

#endif /* WIN32 */

/** @} */

