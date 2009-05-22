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
 * \file libwzd_python_wzd_user.c
 * \brief wzd.user object
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

static PyObject* libwzd_python_wzd_user_new(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_user_get(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_user_set(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_user_addip(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_user_delip(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_user_methods[] = {
  { "new", libwzd_python_wzd_user_new, METH_VARARGS, "" },
  { "get", libwzd_python_wzd_user_get, METH_VARARGS, "" },
  { "set", libwzd_python_wzd_user_set, METH_VARARGS, "" },
  { "addip", libwzd_python_wzd_user_addip, METH_VARARGS, "" },
  { "delip", libwzd_python_wzd_user_delip, METH_VARARGS, "" },
  { NULL, NULL, 0, NULL }
};


static PyObject* libwzd_python_wzd_user_new(UNUSED PyObject *self, PyObject *args)
{
  const char *username, *password, *groupname;

  if (! PyArg_ParseTuple(args, "sss", &username, &password, &groupname)) {
    out_log(
      LEVEL_NORMAL,
      "wzd.user.new(char *username, char *password, char *groupname)\n"
    );
    Py_RETURN_FALSE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.user.new(%s,%s,%s);\n", username, password,
          groupname);
  if (vars_user_new(username, password, groupname, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;	  
  }

  Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_user_get(UNUSED PyObject *self, PyObject *args)
{
  const char *username, *varname;
  char *buffer;
  PyObject *ret_obj;

  if (! PyArg_ParseTuple(args, "ss", &username, &varname)) {
    out_log(LEVEL_NORMAL, "wzd.user.get(char *username, char *varname)\n");
    Py_RETURN_NONE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.user.get(%s,%s);\n", username, varname);

  buffer = wzd_malloc(1024);
  *buffer = '\0';
  
  if ( vars_user_get(username, varname, buffer, 1024, getlib_mainConfig()) != 0)  {
    wzd_free(buffer);
    Py_RETURN_NONE;
  }

  ret_obj = Py_BuildValue("s", buffer);
  wzd_free(buffer);

  return ret_obj;
}

static PyObject* libwzd_python_wzd_user_set(UNUSED PyObject *self, PyObject *args)
{
  const char *username, *varname, *value;

  if (! PyArg_ParseTuple(args, "sss", &username, &varname, &value)) {
    out_log(LEVEL_NORMAL, "wzd.user.set(char *username, char *varname, char *value)\n");
    Py_RETURN_NONE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.user.set(%s,%s,%s);\n", username, varname, value);

  vars_user_set(username, varname, value, 1024, getlib_mainConfig()); /* return nothing ? */
  
  Py_RETURN_NONE;
}

static PyObject* libwzd_python_wzd_user_addip(UNUSED PyObject *self, PyObject *args)
{
  const char *username, *ip;

  if (! PyArg_ParseTuple(args, "ss", &username, &ip)) {
    out_log(LEVEL_NORMAL, "wzd.user.addip(char *username, char *ip)\n");
    Py_RETURN_FALSE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.user.addip(%s,%s);\n", username, ip);

  if (vars_user_addip(username, ip, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_user_delip(UNUSED PyObject *self, PyObject *args)
{
  const char *username, *ip;

  if (! PyArg_ParseTuple(args, "ss", &username, &ip)) {
    out_log(LEVEL_NORMAL, "wzd.user.delip(char *username, char *ip)\n");
    Py_RETURN_FALSE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.user.delip(%s,%s);\n", username, ip);

  if (vars_user_delip(username, ip, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
}

/**
 * @}
 */

