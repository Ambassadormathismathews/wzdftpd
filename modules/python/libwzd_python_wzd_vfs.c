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
 * \file libwzd_python_wzd_vfs.c
 * \brief wzd.vfs object
 * \addtogroup Module_Python
 * @{
 */

#include "libwzd_python.h"

/* wzd.vfs object */
static PyObject* libwzd_python_wzd_vfs_mkdir(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_vfs_rmdir(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_vfs_methods[] = {
  { "mkdir", libwzd_python_wzd_vfs_mkdir, METH_VARARGS, "" },
  { "rmdir", libwzd_python_wzd_vfs_rmdir, METH_VARARGS, "" },
  { NULL, NULL, 0, NULL }
};

/* wzd.vfs.link object */
static PyObject* libwzd_python_wzd_vfs_link_create(PyObject *self, PyObject *args);
static PyObject* libwzd_python_wzd_vfs_link_remove(PyObject *self, PyObject *args);

PyMethodDef libwzd_python_wzd_vfs_link_methods[] = {
  { "create", libwzd_python_wzd_vfs_link_create, METH_VARARGS, ""},
  { "remove", libwzd_python_wzd_vfs_link_remove, METH_VARARGS, ""},
  { NULL, NULL, 0, NULL }
};


static PyObject* libwzd_python_wzd_vfs_mkdir(UNUSED PyObject *self, PyObject *args)
{
  int ret;
  PyObject *real;
  const char *path;
  char real_path[WZD_MAX_PATH + 1];
  
  wzd_context_t *context=GetMyContext();

  if ( ! PyArg_ParseTuple(args, "s|O", &path, &real) ) {
    out_log(LEVEL_HIGH, "wzd.vfs.mkdir(const char *path[, bool real])\n");
    Py_RETURN_FALSE;
  }

  if ( PyObject_IsTrue(real) != 1 ) {
    /* convert to real_path */
    if ( checkpath_new(path, real_path, context) != E_FILE_NOEXIST) {
        Py_RETURN_FALSE;
    }
  } else {
    /* just copy */
    strncpy(real_path, path, sizeof(real_path));
  }

  if ( file_mkdir(real_path, 0755, context) )
    Py_RETURN_FALSE;
  else
    Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_vfs_rmdir(UNUSED PyObject *self, PyObject *args)
{
  int ret;
  PyObject *real;
  const char *path;
  char real_path[WZD_MAX_PATH + 1];
  
  wzd_context_t *context=GetMyContext();

  if ( ! PyArg_ParseTuple(args, "s|O", &path, &real) ) {
    out_log(LEVEL_HIGH, "wzd.vfs.rmdir(const char *path[, bool real])\n");
    Py_RETURN_FALSE;
  }

  if ( PyObject_IsTrue(real) != 1 ) {
    /* convert to real_path */
    if ( checkpath_new(path, real_path, context) != E_FILE_NOEXIST) {
        Py_RETURN_FALSE;
    }
  } else {
    /* just copy */
    strncpy(real_path, path, sizeof(real_path));
  }

  if ( file_rmdir(real_path, context) )
    Py_RETURN_FALSE;
  else
    Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_vfs_link_create(UNUSED PyObject *self, PyObject *args)
{
  Py_RETURN_TRUE;
}

static PyObject* libwzd_python_wzd_vfs_link_remove(UNUSED PyObject *self, PyObject *args)
{
  Py_RETURN_TRUE;
}

