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
 * the following code is NOT reentrant at all (current_context !! )
 * I should use locks and/or use interpreter slaves
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


#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>


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


extern void boot_DynaLoader (pTHX_ CV* cv);


/***** Private vars ****/
static PerlInterpreter * my_perl=NULL;
static wzd_context_t * current_context=NULL;

#define PERL_ARGS        "wzd::args"
#define TCL_CURRENT_USER "wzd_current_user"
#define TCL_REPLY_CODE  "wzd_reply_code"
#define TCL_HAS_REPLIED "wzd_replied"

/***** Private fcts ****/
static void do_perl_help(wzd_context_t * context);
static int perl_init(void);
static int execute_perl( SV *function, const char *args);
static void xs_init(pTHX);

/***** EVENT HOOKS *****/
static wzd_hook_reply_t perl_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args);
static int perl_hook_logout(unsigned long event_id, wzd_context_t *context, const char *username);

/***** PROTO HOOKS *****/
static int perl_hook_protocol(const char *file, const char *args);

/***** PERL commands ***/
static XS(XS_wzd_test);
static XS(XS_wzd_ftp2sys);
static XS(XS_wzd_killpath);
static XS(XS_wzd_putlog);
static XS(XS_wzd_send_message_raw);
static XS(XS_wzd_send_message);
static XS(XS_wzd_stat);
static XS(XS_wzd_vars);
static XS(XS_wzd_vars_group);
static XS(XS_wzd_vars_shm);
static XS(XS_wzd_vars_user);
static XS(XS_wzd_vfs);

/***** slaves *****/
static int _perl_set_slave(void *context);

struct _slave_t {
  short is_allocated;
  void * context;
  PerlInterpreter * interp;
};

#define MAX_SLAVES 256
static struct _slave_t _slaves[MAX_SLAVES];

/***********************/
MODULE_NAME(perl);
MODULE_VERSION(101);

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
  if (perl_init()) {
    out_log(LEVEL_HIGH,"PERL could not create interpreter\n");
    return -1;
  }
  memset(_slaves, 0, MAX_SLAVES*sizeof(struct _slave_t));

  hook_add(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&perl_hook_site);
  hook_add(&getlib_mainConfig()->hook,EVENT_LOGOUT,(void_fct)&perl_hook_logout);
  hook_add_protocol("perl:",5,&perl_hook_protocol);
  out_log(LEVEL_INFO,"PERL module loaded\n");
  return 0;
}

void WZD_MODULE_CLOSE(void)
{
  perl_destruct(my_perl);
  perl_free(my_perl);
  my_perl = NULL;
  out_log(LEVEL_INFO,"PERL module unloaded\n");
}



static wzd_hook_reply_t perl_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args)
{
  SV *val;

  if (strcasecmp(token,"site_perl")==0) {
    if (!my_perl) return 0;
    if (!args || strlen(args)==0) { do_perl_help(context); return EVENT_HANDLED; }

    if (_perl_set_slave(context)) return EVENT_ERROR;
      
    /* send reply header */
    send_message_raw("200-\r\n",context);

    /* exec string */
    val = eval_pv(args, FALSE);

    if (SvTRUE(val))
      send_message_with_args(200,context,"PERL command ok");
    else
      send_message_with_args(200,context,"PERL command reported errors");
    return EVENT_HANDLED;
  }
  return EVENT_IGNORED;
}

/** \bug this code is not reentrant, be carefull with _perl_set_slave ! */
static int perl_hook_logout(unsigned long event_id, wzd_context_t * context, const char *username)
{
  int i;

  /* we need to create one, find a free slave */
  for (i=0; i<MAX_SLAVES; i++)
  {
    if ( _slaves[i].is_allocated && _slaves[i].context == context )
    {
      perl_destruct(_slaves[i].interp);
      perl_free(_slaves[i].interp);
      _slaves[i].context = NULL;
      _slaves[i].is_allocated = 1;
      
      break;
    }
  }

  return 0;
}

static int perl_hook_protocol(const char *file, const char *args)
{
  wzd_context_t * context;
  wzd_user_t * user;
  unsigned int reply_code;
  SV * perl_args;

  current_context = context = GetMyContext();
  user = GetUserByID(context->userid);
  reply_code = hook_get_current_reply_code();

  if (_perl_set_slave(context)) return -1;

  /* prepare args */
  perl_args = get_sv("wzd::args",TRUE);
  if (args) {
    sv_setpv(perl_args, args);
  }

  execute_perl(newSVpvn("Embed::load", 11), file);

/*  SvREFCNT_dec(perl_args);*/ /* NO !! this will segfault on second call ! */

  current_context = NULL;

  return 0;
}

static void do_perl_help(wzd_context_t * context)
{
  send_message_raw("501-\r\n",context);
  send_message_raw("501-perl commands\r\n",context);
  send_message_raw("501- site perl <perl_command>\r\n",context);
  send_message_raw("501 \r\n",context);
}









/******* PERL helpers ********/



static int perl_init(void)
{
  const char perl_definitions[] = {
"\n"
"$SIG{__WARN__} = sub {\n"
"  local $, = \"\\n\";\n"
"  my ($package, $line, $sub) = caller(1);\n"
"  wzd::send_message( \"warning from ${package}::${sub} at line $line.\" );\n"
"  wzd::send_message( @_ );\n"
"};\n"
"\n"
"sub Embed::load {\n"
"  my $file = shift @_;\n"
"\n"
"  if( open FH, $file ) {\n"
"	 my $data = do {local $/; <FH>};\n"
"	 close FH;\n"
"\n"
"	 eval $data;\n"
"\n"
"	 if( $@ ) {\n"
"		# something went wrong\n"
"		print( \"Error loading '$file':\\n$@\n\" );\n"
"		return 1;\n"
"	 }\n"
"\n"
"  } else {\n"
"\n"
"	 print( \"Error opening '$file': $!\\n\" );\n"
"	 return 2;\n"
"  }\n"
"\n"
"  return 0;\n"
"}\n"
  };
  
  char * perl_args[] = { "", "-e", "0", "-w" };

  if (my_perl) /* init already done ! */
    return -1;

  my_perl = perl_alloc();
  if (!my_perl) return -1;
  perl_construct(my_perl);

  /* set to 4 to have warnings */
  perl_parse(my_perl, xs_init, 3, perl_args, NULL);

  /* now initialize the perl interpreter by loading the
   * perl_definitions array.
   */
  eval_pv(perl_definitions, TRUE);

  return 0;
}

static void xs_init(pTHX)
{
  char *file = __FILE__;

  /* This one allows dynamic loading of perl modules in perl
   * scripts by the 'use perlmod;' construction
   */
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);

  newXS("wzd::test", XS_wzd_test, "wzd");
  newXS("wzd::ftp2sys", XS_wzd_ftp2sys, "wzd");
  newXS("wzd::killpath", XS_wzd_killpath, "wzd");
  newXS("wzd::putlog", XS_wzd_putlog, "wzd");
  newXS("wzd::send_message_raw", XS_wzd_send_message_raw, "wzd");
  newXS("wzd::send_message", XS_wzd_send_message, "wzd");
  newXS("wzd::stat", XS_wzd_stat, "wzd");
  newXS("wzd::vars", XS_wzd_vars, "wzd");
  newXS("wzd::vars_group", XS_wzd_vars_group, "wzd");
  newXS("wzd::vars_shm", XS_wzd_vars_shm, "wzd");
  newXS("wzd::vars_user", XS_wzd_vars_user, "wzd");
  newXS("wzd::vfs", XS_wzd_vfs, "wzd");
}

static int execute_perl( SV *function, const char *args)
{
  int count, ret=1;
  SV *sv;

  dSP;
  ENTER;
  SAVETMPS;

  PUSHMARK (SP);
  XPUSHs (newSVpvn (args, strlen(args)));
  PUTBACK;

  count = call_sv(function, G_EVAL | G_KEEPERR | G_SCALAR);
  SPAGAIN;

  sv = GvSV(gv_fetchpv("@", TRUE, SVt_PV));
  if (SvTRUE(sv)) {
    /* perl error */
    POPs; /* remove undef from the top of the stack */
  }
  else if (count != 1) {
    /* error, we expected only 1 value */
  }
  else {
    ret = POPi;
  }

  PUTBACK;
  FREETMPS;
  LEAVE;

  return ret;
}

/***** slaves *****/

/** @brief select slave for current context.
 *
 * create the slave interpreter if needed
 *
 * \bug on user logout or timeout we need to destroy slave
 * \bug this code is not reentrant
 */
static int _perl_set_slave(void *context)
{
  int i;
  int found;

  found = 0;

  for (i=0; i<MAX_SLAVES; i++)
  {
    if (_slaves[i].is_allocated && _slaves[i].context == context)
    { found = 1; break; }
  }

  current_context = context;
  if (found) {
    PERL_SET_CONTEXT(_slaves[i].interp);
    return 0;
  }

  /* we need to create one, find a free slave */
  for (i=0; i<MAX_SLAVES; i++)
  {
    if ( ! _slaves[i].is_allocated )
    {
      PERL_SET_CONTEXT(my_perl);

      _slaves[i].is_allocated = 1;
      _slaves[i].context = context;
#ifdef WIN32
      _slaves[i].interp = perl_clone(my_perl,CLONEf_CLONE_HOST);
#else
      _slaves[i].interp = perl_clone(my_perl,0);
#endif
      /* see perlapi (1) for more info, this flag is needed for win32 */
      
      PERL_SET_CONTEXT(_slaves[i].interp);

      return 0;
    }
  }

  return -1; /* no more available slaves, you must be tyrannic to use them all ! */
}




/******* PERL functions ********/



static XS(XS_wzd_test)
{
/*  char * cmd = NULL;*/

  dXSARGS;

    printf("Hello from c (items: %d)\n",(int)items);

  XSRETURN_EMPTY;
}

static XS(XS_wzd_ftp2sys)
{
  char path[WZD_MAX_PATH+1];
  char * text;
  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 1) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;

  text = SvPV_nolen(ST(0));

  if ( checkpath_new(text, path, current_context) ) {
    XSRETURN_UNDEF;
  }

  XSRETURN_PV(path);
}

static XS(XS_wzd_killpath)
{
  char * text;
  int ret;
  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 1) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;

  text = SvPV_nolen(ST(0));

  if (!strcmp(text,"-r") || !strcmp(text,"--real")) {
    /* ex: killpath -r c:\real */
    if (items < 2) XSRETURN_UNDEF;

    /** \todo print error message */
    if ( ! SvPOK(ST(1)) )
      XSRETURN_UNDEF;

    text = SvPV_nolen(ST(1));

    ret = killpath (text,current_context);
  } else {
    char * realpath;
    realpath = malloc(WZD_MAX_PATH+1);
    if ( checkpath(text, realpath, current_context) ) {
      XSRETURN_UNDEF;
    }
    ret = killpath (realpath,current_context);
    free(realpath);
  }
  if ( ret != E_OK && ret != E_USER_NOBODY ) {
    XSRETURN_NO;
  }

  XSRETURN_YES;
}

/**
 * example: wzd::putlog(5,"message\n");
 *  or    : wzd::putlog 5,"message\n";
 */
static XS(XS_wzd_putlog)
{
  char * text;
  int level;
  STRLEN length;

  dXSARGS;

  if (!current_context) XSRETURN_NO;
  if (items < 2) XSRETURN_NO;

  /** \todo print error message */
  if ( ! SvIOK(ST(0)) )
    XSRETURN_NO;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_NO;

  level = SvIV(ST(0));
  text = SvPV(ST(1),length);

  /** \todo XXX we could format the string using argv[2,] */

  /* replace cookies ? */

  out_log( level, text );

  XSRETURN_YES;
}

static XS(XS_wzd_send_message_raw)
{
  char *text;
  int ret;

  dXSARGS;

  if (!current_context) XSRETURN_NO;
  if (items < 1) XSRETURN_NO;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_NO;

  text = SvPV_nolen(ST(0));

  ret = send_message_raw(text,current_context);

  if (ret)
    XSRETURN_YES;
  else
    XSRETURN_NO;
}


static XS(XS_wzd_send_message)
{
  char *text;
  char *ptr;
  int ret;
  wzd_user_t * user = current_context ? GetUserByID(current_context->userid) : NULL;
  wzd_group_t * group = current_context ? GetGroupByID(user->groups[0]) : NULL;

  dXSARGS;

  if (!current_context) XSRETURN_NO;
  if (items < 1) XSRETURN_NO;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_NO;

  text = SvPV_nolen(ST(0));

  /** \todo XXX we could format the string using argv[2,] */

  ptr = malloc(4096);
  *ptr = '\0';

  cookie_parse_buffer(text,user,group,current_context,ptr,4096);

  ret = send_message_raw(ptr,current_context);
  free(ptr);

  if (ret)
    XSRETURN_YES;
  else
    XSRETURN_NO;
}


static XS(XS_wzd_stat)
{
  char * text;
  char path[WZD_MAX_PATH+1];
  char * buffer;
  struct wzd_file_t * file;

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 1) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;

  text = SvPV_nolen(ST(0));


  /* use checkpath, we don't want to resolve links */
  if (!strcmp(text,"-r") || !strcmp(text,"--real")) {
    /* ex: vfs read -r c:\real */
    if (items < 2) XSRETURN_UNDEF;

  /** \todo print error message */
    if ( ! SvPOK(ST(1)) )
      XSRETURN_UNDEF;

    text = SvPV_nolen(ST(1));
    strncpy(path, text, WZD_MAX_PATH);
  } else {
    if ( checkpath(text, path, current_context) ) {
      XSRETURN_UNDEF;
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

  XSRETURN_PV(path);
}

static XS(XS_wzd_vars)
{
  char *command, *text, *value;
  int ret;
  char buffer[1024];

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 2) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_UNDEF;

  command = SvPV_nolen(ST(0));
  text = SvPV_nolen(ST(1));

  if (!strcmp(command,"get")) {

    ret = vars_get(text,buffer,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  } else if (!strcmp(command,"set")) {
    if (items < 3) XSRETURN_UNDEF;
    /** \todo print error message */
    if ( ! SvPOK(ST(2)) )
      XSRETURN_UNDEF;
    value = SvPV_nolen(ST(2));
    ret = vars_set(text,(void*)value,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  }

  XSRETURN_UNDEF;
}

static XS(XS_wzd_vars_group)
{
  char *command, *groupname, *text, *value;
  int ret;
  char buffer[1024];

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 3) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(2)) )
    XSRETURN_UNDEF;

  command = SvPV_nolen(ST(0));
  groupname = SvPV_nolen(ST(1));
  text = SvPV_nolen(ST(2));

  if (!strcmp(command,"get")) {
    ret = vars_group_get(groupname,text,buffer,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  } else if (!strcmp(command,"set")) {
    if (items < 4) XSRETURN_UNDEF;
    /** \todo print error message */
    if ( ! SvPOK(ST(3)) )
      XSRETURN_UNDEF;
    value = SvPV_nolen(ST(3));
    ret = vars_group_set(groupname,text,(void*)value,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  } else if (!strcmp(command,"new")) { /* new user creation */
    ret = vars_group_new(groupname,getlib_mainConfig());
    /** \todo handle return */
    if (!ret)
      XSRETURN_PV("command ok");
    else
      XSRETURN_UNDEF;
  }

  XSRETURN_UNDEF;
}

static XS(XS_wzd_vars_shm)
{
  char *command, *text, *value;
  int ret;
  char buffer[1024];

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 2) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_UNDEF;

  command = SvPV_nolen(ST(0));
  text = SvPV_nolen(ST(1));

  if (!strcmp(command,"get")) {

    ret = vars_shm_get(text,buffer,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  } else if (!strcmp(command,"set")) {
    if (items < 3) XSRETURN_UNDEF;
    /** \todo print error message */
    if ( ! SvPOK(ST(2)) )
      XSRETURN_UNDEF;
    value = SvPV_nolen(ST(2));
    ret = vars_shm_set(text,(void*)value,strlen(value)+1,getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(value);
    else
      XSRETURN_UNDEF;
  }

  XSRETURN_UNDEF;
}

static XS(XS_wzd_vars_user)
{
  char *command, *username, *text, *value;
  int ret;
  char buffer[1024];

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 3) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_UNDEF;
  if ( ! SvPOK(ST(2)) )
    XSRETURN_UNDEF;

  command = SvPV_nolen(ST(0));
  username = SvPV_nolen(ST(1));
  text = SvPV_nolen(ST(2));

  if (!strcmp(command,"get")) {
    ret = vars_user_get(username,text,buffer,sizeof(buffer),getlib_mainConfig());
    if (!ret)
      XSRETURN_PV(buffer);
    else
      XSRETURN_UNDEF;
  } else { /* modification command */
    ret = 1;

    if (!strcmp(command,"set")) {
      if (items < 4) XSRETURN_UNDEF;
      /** \todo print error message */
      if ( ! SvPOK(ST(3)) )
        XSRETURN_UNDEF;
      value = SvPV_nolen(ST(3));

      ret = vars_user_set(username,text,(void*)value,1024,getlib_mainConfig());
    } else if (!strcmp(command,"new")) { /* new user creation */
      if (items < 4) XSRETURN_UNDEF;
      /** \todo print error message */
      if ( ! SvPOK(ST(3)) )
        XSRETURN_UNDEF;
      value = SvPV_nolen(ST(3));

      ret = vars_user_new(username,text,value,getlib_mainConfig());
      /** \todo handle return */
    } else if (!strcmp(command,"addip")) { /* add new ip */
      ret = vars_user_addip(username,text,getlib_mainConfig());
      /** \todo handle return */
    } else if (!strcmp(command,"delip")) { /* remove ip */
      ret = vars_user_delip(username,text,getlib_mainConfig());
      /** \todo handle return */
    }

    if (!ret)
      XSRETURN_PV("command ok");
    else
      XSRETURN_UNDEF;
  } /* modification command */

  XSRETURN_UNDEF;
}


static XS(XS_wzd_vfs)
{
  char *command1, *arg1, *arg2;
  int ret;
  char buffer_real[WZD_MAX_PATH+1];
  char buffer_link[WZD_MAX_PATH+1];
  int pos1, pos2;

  dXSARGS;

  if (!current_context) XSRETURN_UNDEF;
  if (items < 2) XSRETURN_UNDEF;

  /** \todo print error message */
  if ( ! SvPOK(ST(0)) )
    XSRETURN_NO;
  if ( ! SvPOK(ST(1)) )
    XSRETURN_NO;

  command1 = SvPV_nolen(ST(0));
  arg1 = SvPV_nolen(ST(1));

  ret = 1;

  /* XXX all following commands wants an absolute path */
  if (!strcmp(command1,"mkdir")) {
    pos1 = 1;
    if (!strcmp(arg1,"-r") || !strcmp(arg1,"--real")) {
      /* ex: vfs link mkdir -r c:\real */
      pos1++;
      if (items <= pos1) XSRETURN_NO;
      /** \todo print error message */
      if ( ! SvPOK(ST(pos1)) )
        XSRETURN_NO;
      arg1 = SvPV_nolen(ST(pos1));

      strncpy(buffer_real, arg1, sizeof(buffer_real));
    } else {
      if (checkpath_new(arg1,buffer_real,current_context) != E_FILE_NOEXIST)
        XSRETURN_NO;
    }
    ret = file_mkdir(buffer_real, 0755, current_context); /** \todo remove hardcoded umask */
  }
  else if (!strcmp(command1,"rmdir")) {
    pos1 = 1;
    if (!strcmp(arg1,"-r") || !strcmp(arg1,"--real")) {
      /* ex: vfs link mkdir -r c:\real */
      pos1++;
      if (items <= pos1) XSRETURN_NO;
      /** \todo print error message */
      if ( ! SvPOK(ST(pos1)) )
        XSRETURN_NO;
      arg1 = SvPV_nolen(ST(pos1));

      strncpy(buffer_real, arg1, sizeof(buffer_real));
    } else {
      if (checkpath_new(arg1,buffer_real,current_context) != E_FILE_NOEXIST)
        XSRETURN_NO;
    }
    ret = file_rmdir(buffer_real,current_context);
  }

  /** \todo XXX FIXME the following is not possible in perl */
#if 0
  else if (!strcmp(command1,"read")) {
    return tcl_stat(data, interp, argc-1, argv+1); /* pass through tcl_stat */
  }
#endif
  else if (!strcmp(command1,"link")) {
    /* TODO move this code to symlink_create ? */
    if (items < 3) XSRETURN_NO;
    /** \todo print error message */
    if ( ! SvPOK(ST(2)) )
      XSRETURN_UNDEF;

    arg2 = SvPV_nolen(ST(2));

    if (!strcmp(arg1,"create")) {
      pos1 = 2; /* position of existing dir */
      pos2 = 3; /* position of link name */

      /** \todo print error message */
      if (items < pos2+1) XSRETURN_NO;

      arg1 = arg2;

      if (!strcmp(arg1,"-r") || !strcmp(arg1,"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos1++; pos2++;

        if (items < pos2+1) XSRETURN_NO;

        /** \todo print error message */
        if ( ! SvPOK(ST(pos1)) ) XSRETURN_UNDEF;
        arg1 = SvPV_nolen(ST(pos1));

        strncpy(buffer_real, arg1, sizeof(buffer_real));
      } else {
        if (checkpath_new(arg1,buffer_real,current_context))
          XSRETURN_UNDEF;
      }

      if (items < pos2+1) XSRETURN_NO;

      /** \todo print error message */
      if ( ! SvPOK(ST(pos2)) ) XSRETURN_UNDEF;
      arg2 = SvPV_nolen(ST(pos2));

      if (!strcmp(arg2,"-r") || !strcmp(arg2,"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos2++;

        if (items < pos2+1) XSRETURN_NO;

        /** \todo print error message */
        if ( ! SvPOK(ST(pos2)) ) XSRETURN_UNDEF;
        arg2 = SvPV_nolen(ST(pos2));

        strncpy(buffer_link, arg2, sizeof(buffer_link));
      } else {
        if (checkpath_new(arg2,buffer_link,current_context) != E_FILE_NOEXIST)
          XSRETURN_UNDEF;
      }

      REMOVE_TRAILING_SLASH(buffer_link);
      REMOVE_TRAILING_SLASH(buffer_real);
      ret = symlink_create(buffer_real,buffer_link);
    }
    else if (!strcmp(arg1,"remove")) {
      /* we need to convert arg to the link name, _without_ converting the last
       * component (the link name itself), or the remove will fail
       */
      pos2 = 3;
      if (!strcmp(arg2,"-r") || !strcmp(arg2,"--real")) {
        /* ex: vfs link create -r c:\real linkname */
        pos2++;

        if (items < pos2+1) XSRETURN_NO;

        /** \todo print error message */
        if ( ! SvPOK(ST(pos2)) ) XSRETURN_UNDEF;
        arg2 = SvPV_nolen(ST(pos2));

        strncpy(buffer_link, arg2, sizeof(buffer_link));
      } else {
        if (checkpath(arg2,buffer_link,current_context))
          XSRETURN_UNDEF;
      }
      ret = symlink_remove(buffer_link);
    }
    else
      XSRETURN_UNDEF;
  }
  else
    ret = 1;
  
  if (!ret)
    XSRETURN_YES;
  else
    XSRETURN_NO;
}

