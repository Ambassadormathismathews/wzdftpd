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
 * \file libwzd_python_wzd_group.c
 * \brief wzd.group object
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

static PyObject* libwzd_python_wzd_group_new(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_group_get(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_group_set(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_group_methods[] = {
  { "new", libwzd_python_wzd_group_new, METH_VARARGS, "" },
  { "get", libwzd_python_wzd_group_get, METH_VARARGS, "" },
  { "set", libwzd_python_wzd_group_set, METH_VARARGS, "" },
  { NULL, NULL, 0, NULL }
};

static PyObject* libwzd_python_wzd_group_new(UNUSED PyObject *self, PyObject *args)
{
  const char *group_name;

  if (! PyArg_ParseTuple(args, "s", &group_name)) {
    out_log(LEVEL_HIGH, "wzd.group.new(char *group_name)\n");
    Py_RETURN_FALSE;
  }

  if ( vars_group_new(group_name, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_group_get(UNUSED PyObject *self, PyObject *args)
{
  char *buffer;
  const char *group_name, *var_name;
  PyObject *ret_obj;

  if (! PyArg_ParseTuple(args, "ss", &group_name, &var_name)) {
    out_log(LEVEL_HIGH, "wzd.group.get(char *group_name, char *var_name)\n");
    Py_RETURN_NONE;
  }

  buffer = wzd_malloc(1024);
  *buffer = '\0';

  if (vars_group_get(group_name, var_name, buffer, 1024, getlib_mainConfig()) != 0) {
    wzd_free(buffer);
    Py_RETURN_NONE;
  }

  ret_obj = Py_BuildValue("s", buffer);
  wzd_free(buffer);

  return ret_obj;
}

static PyObject* libwzd_python_wzd_group_set(UNUSED PyObject *self, PyObject *args)
{
  const char *group_name, *var_name, *var_value;

  if (! PyArg_ParseTuple(args, "sss", &group_name, &var_name, &var_value)) {
    out_log(LEVEL_HIGH, "wzd.group.set(char *group_name, char *var_name, char *var_value)\n");
    Py_RETURN_FALSE;
  }

  if ( vars_group_set(group_name, var_name, var_value, 1024, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;
  }
  
  Py_RETURN_TRUE;
}

