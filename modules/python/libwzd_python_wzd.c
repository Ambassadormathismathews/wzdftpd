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
 * \file libwzd_python_wzd.c
 * \brief wzd object
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

static PyObject* libwzd_python_wzd_chgrp(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_chmod(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_chown(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_ftp2sys(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_killpath(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_putlog(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_send_message(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_send_message_raw(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_stat(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_vars(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_vfs(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_methods[] = {
  { "chgrp", libwzd_python_wzd_chgrp, METH_VARARGS, "" },
  { "chmod", libwzd_python_wzd_chmod, METH_VARARGS, "" },
  { "chown", libwzd_python_wzd_chown, METH_VARARGS, "" },
  { "ftp2sys", libwzd_python_wzd_ftp2sys, METH_VARARGS, ""},
  { "killpath", libwzd_python_wzd_killpath, METH_VARARGS, ""},
  { "putlog", libwzd_python_wzd_putlog, METH_VARARGS, ""},
  { "send_message", libwzd_python_wzd_send_message, METH_VARARGS, ""},
  { "send_message_raw", libwzd_python_wzd_send_message_raw, METH_VARARGS, ""},
  { "stat", libwzd_python_wzd_stat, METH_VARARGS, ""},
  { "vars", libwzd_python_wzd_vars, METH_VARARGS, ""},
  { "vfs", libwzd_python_wzd_vfs, METH_VARARGS, ""},
  { NULL, NULL, 0, NULL }
};

static PyObject* libwzd_python_wzd_chgrp(UNUSED PyObject *self, UNUSED PyObject *args)
{
  wzd_context_t *context=GetMyContext();

  char *arg_groupname=NULL, *arg_path=NULL;
  char path[WZD_MAX_PATH+1];

  if ( ! PyArg_ParseTuple(args, "ss", &arg_groupname, &arg_path)) {
    PyErr_SetString(PyExc_TypeError, "wzd.chgrp(groupname, path)");
    return NULL;
  }

  if (checkpath_new(arg_path, path, context)) {
    //PyErr_SetString(WzdExcPath, "could not retrieve path");
    //return NULL;
    Py_RETURN_NONE;
  }
  if (file_chown(path, NULL, arg_groupname, context)) {
    //PyErr_SetString(WzdExcChown, "could not chgrp");
    //return NULL;
    Py_RETURN_NONE;
  }
  Py_RETURN_NONE;

}

static PyObject* libwzd_python_wzd_chmod(UNUSED PyObject *self, UNUSED PyObject *args)
{
  
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_chown(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_ftp2sys(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_killpath(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
;
}

static PyObject* libwzd_python_wzd_putlog(UNUSED PyObject *self, PyObject *args)
{
  const char *message;
  int level;
  
  if (! PyArg_ParseTuple(args, "is", &level, &message)) {
    out_log(LEVEL_NORMAL, "wzd.putlog(int level, char *message)\n");
    Py_RETURN_NONE;
  }
  
  out_log(level, "%s", message);

  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_send_message(UNUSED PyObject *self, PyObject *args)
{
  char *message=NULL, *ptr=NULL;
  wzd_context_t * context = GetMyContext();
  wzd_user_t * user = context ? GetUserByID(context->userid) : NULL;
  wzd_group_t * group = context ? GetGroupByID(user->groups[0]) : NULL;

  if (! PyArg_ParseTuple(args, "s", &message)) {
    out_log(LEVEL_NORMAL, "wzd.send_message(char *message)\n");
    Py_RETURN_NONE;
  }

  ptr = malloc(4096);
  *ptr = '\0';

  cookie_parse_buffer(message, user, group, context, ptr, 4096);
  send_message_raw(ptr, context);
  free(ptr);

  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_send_message_raw(UNUSED PyObject *self, PyObject *args)
{
  const char *message;

  if (! PyArg_ParseTuple(args, "s", &message)) {
    out_log(LEVEL_NORMAL, "wzd.send_message(char *message)\n");
    Py_RETURN_NONE;
  }
  send_message_raw(message, GetMyContext());

  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_stat(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_vars(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_vfs(UNUSED PyObject *self, UNUSED PyObject *args)
{
  Py_RETURN_NONE;
}

/**
 * @}
 */

