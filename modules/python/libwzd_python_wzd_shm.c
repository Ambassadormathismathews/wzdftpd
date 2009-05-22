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
 * \file libwzd_python_wzd_shm.c
 * \brief wzd.shm object
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

static PyObject* libwzd_python_wzd_shm_get(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_shm_set(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_shm_methods[] = {
  { "get", libwzd_python_wzd_shm_get, METH_VARARGS, "" },
  { "set", libwzd_python_wzd_shm_set, METH_VARARGS, "" },
  { NULL, NULL, 0, NULL }
};


static PyObject* libwzd_python_wzd_shm_get(UNUSED PyObject *self, PyObject *args)
{
  char *buffer;
  const char *name;
  PyObject *ret_obj;

  if (! PyArg_ParseTuple(args, "s", &name)) {
    out_log(LEVEL_NORMAL, "wzd.shm.get(const char *name)");
    Py_RETURN_NONE;
  }
  
  out_log(LEVEL_FLOOD, "wzd.shm.get(%s)", name);

  buffer = wzd_malloc(1024);
  *buffer = '\0';
  if (vars_shm_get(name, buffer, 1024, getlib_mainConfig()) != 0) {
    wzd_free(buffer);
    Py_RETURN_NONE;
  }
 
  ret_obj = Py_BuildValue("s", buffer);
  wzd_free(buffer);

  return ret_obj;
}

static PyObject* libwzd_python_wzd_shm_set(UNUSED PyObject *self, PyObject *args)
{
  int ret;
  const char *name, *value;

  if (! PyArg_ParseTuple(args, "ss", &name, &value)) {
    out_log(LEVEL_NORMAL, "wzd.shm.set(const char *name, const char *value)");
    Py_RETURN_FALSE;
  }

  out_log(LEVEL_FLOOD, "wzd.shm.set(%s, %s)", name, value);
  if (vars_shm_set(name, (void*) value, strlen(value)+1, getlib_mainConfig()) != 0) {
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
}

/**
 * @}
 */

