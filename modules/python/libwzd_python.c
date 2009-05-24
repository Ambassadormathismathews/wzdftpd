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

/**
 * \file libwzd_python.c
 * \brief Python module functions
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

static int libwzd_python_hook_protocol(const char *file, const char *args);

/***********************/
MODULE_NAME(python);
MODULE_VERSION(1);
/***********************/

static PyObject* libwzd_python_catch(UNUSED PyObject *self, PyObject *args)
{
  const char *errmsg;

  if (! PyArg_ParseTuple(args, "s", &errmsg)) {
    Py_RETURN_NONE;
  }

  out_log(LEVEL_FLOOD, "python: %s\n", errmsg);

  Py_RETURN_NONE;
}

static PyMethodDef wzd_catch_methods[] = {
  { "write", libwzd_python_catch, METH_VARARGS, ""},
  { NULL, NULL, 0, NULL }
};

int WZD_MODULE_INIT(void)
{
  Py_SetProgramName("wzdftpd");
  PyEval_InitThreads();
  Py_Initialize();
  PyEval_ReleaseLock();
  
  libwzd_python_wzd_exc_init();

  /* registre hook_protocol */
  hook_add_protocol("python:", 7, libwzd_python_hook_protocol);

  out_log(LEVEL_INFO, "Python loaded. (%s)\n", Py_GetVersion());
   
  return 0;
}

void WZD_MODULE_CLOSE(void)
{
  PyEval_AcquireLock();
  Py_Finalize();
  out_log(LEVEL_INFO, "Python closed.\n");
}

static int libwzd_python_hook_protocol(const char *file, const char *args)
{
  FILE *f=NULL;
  int argc;
  char **argv, *str_args, *token;
  PyGILState_STATE state;
  PyObject *wzd, *wzd_group, *wzd_user, *wzd_shm, *catch, *sys, *level;

  out_log(LEVEL_FLOOD, "python_hook %s(%s)\n", file, args);
 
  f = fopen(file, "r");
  if (!f) {
    out_log(LEVEL_HIGH, "python hook can't open '%s': %s\n", file, strerror(errno));
    send_message_raw("200 - python script not found.\n", GetMyContext());
    return 0;
  }

  state = PyGILState_Ensure();

  /* wzd object */
  wzd = Py_InitModule("wzd", libwzd_python_wzd_methods);

  /* try to create a level object */
  level = Py_InitModule("__wzd_level", NULL);
  PyObject_SetAttrString(level, "lowest", PyLong_FromLong(LEVEL_LOWEST));
  PyObject_SetAttrString(level, "flood", PyLong_FromLong(LEVEL_FLOOD));
  PyObject_SetAttrString(level, "info", PyLong_FromLong(LEVEL_INFO));
  PyObject_SetAttrString(level, "normal", PyLong_FromLong(LEVEL_NORMAL));
  PyObject_SetAttrString(level, "high", PyLong_FromLong(LEVEL_HIGH));
  PyObject_SetAttrString(level, "critical", PyLong_FromLong(LEVEL_CRITICAL));

  PyObject_SetAttrString(wzd, "level", level);
  

  /* wzd.exc object */
  //PyObject_SetAttrString(wzd, "exc", wzd_exc);
  /* wzd.group object */
  wzd_group = Py_InitModule("__wzd_group", libwzd_python_wzd_group_methods);
  PyObject_SetAttrString(wzd, "group", wzd_group);
  /* wzd.user object */
  wzd_user = Py_InitModule("__wzd_user", libwzd_python_wzd_user_methods);
  PyObject_SetAttrString(wzd, "user", wzd_user);
  /* wzd.shm object */
  wzd_shm = Py_InitModule("__wzd_shm", libwzd_python_wzd_shm_methods);
  PyObject_SetAttrString(wzd, "shm", wzd_shm);
  
  /* set argv */
  argc = 0;
  argv = malloc(sizeof(char *) * 2);
  argv[argc++] = strdup(file);
  str_args = strdup(args);

  token = strtok(str_args, " \t\n");
  while (token) {
    argv = realloc(argv, sizeof(char *) * (argc + 2));
    argv[argc++] = token;
    token = strtok(NULL, " \t\n");
  }
  argv[argc] = NULL;

  PySys_SetArgv(argc, argv);

  /* replace stderr, stdout */
  sys = PyImport_ImportModule("sys");
  catch = Py_InitModule("__wzd_catch", wzd_catch_methods);
  PyObject_SetAttrString(sys, "stdout", catch);
  PyObject_SetAttrString(sys, "stderr", catch);

  /* run */
  if ( PyRun_SimpleFile(f, file) != 0) {
   out_log(LEVEL_HIGH, "python can't parse '%s'\n", file);
  }

  PyGILState_Release(state);

  /* free argv stuff */
  free(argv[0]);
  free(argv);
  free(str_args);

  fclose(f);
  return 0;
}

