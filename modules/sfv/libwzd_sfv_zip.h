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
/* This file was adapted and modified from the 'minizip' example
 * in the zlib distribution, and is copyrighted (c) 1998 Gilles Vollant
 * Original license terms are:
 * Condition of use and distribution are the same than zlib :
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgment in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#ifndef __LIBWZD_SFV_ZIP_H__
#define __LIBWZD_SFV_ZIP_H__

#ifdef HAVE_ZLIB

#include <zlib.h>

typedef voidp zipFile;

#define ZIP_OK                  (0)
#define ZIP_END_OF_LIST_OF_FILE (-100)
#define ZIP_ERRNO               (Z_ERRNO)
#define ZIP_EOF                 (0)
#define ZIP_PARAMETERERROR      (-102)
#define ZIP_BADZIPFILE          (-103)
#define ZIP_INTERNALERROR       (-104)
#define ZIP_CRCERROR            (-105)

/* tm_zip contain date/time info */
typedef struct {
  unsigned int tm_sec;          /* seconds after the minute - [0,59] */
  unsigned int tm_min;          /* minutes after the hour - [0,59] */
  unsigned int tm_hour;         /* hours since midnight - [0,24] */
  unsigned int tm_mday;         /* day of the month - [1,31] */
  unsigned int tm_mon;          /* months since January - [0,11] */
  unsigned int tm_year;         /* years - [1980..2044] */
} tm_zip;

typedef struct {
  unsigned long number_entry; /* total number of entries in the central dir on this disk */
  unsigned long size_comment; /* size of the global comment in the zipfile */
} zip_global_info;

typedef struct {
  unsigned long version;                /* version made by                      2 bytes */
  unsigned long version_needed;         /* version needed to extract            2 bytes */
  unsigned long flag;                   /* general purpose bit flag             2 bytes */
  unsigned long compression_method;     /* compression method                   2 bytes */
  unsigned long dosDate;                /* last mod file date in dos fmt        4 bytes */
  unsigned long crc;                    /* crc-32                               4 bytes */
  unsigned long compressed_size;        /* compressed size                      4 bytes */
  unsigned long uncompressed_size;      /* uncompressed size                    4 bytes */
  unsigned long size_filename;          /* filename length                      2 bytes */
  unsigned long size_file_extra;        /* extra field length                   2 bytes */
  unsigned long size_file_comment;      /* file comment length                  2 bytes */

  unsigned long disk_num_start;         /* disk number start                    2 bytes */
  unsigned long internal_fa;            /* internal file attributes             2 bytes */
  unsigned long external_fa;            /* external file attributes             4 bytes */

  tm_zip tmu_date;
} zip_file_info;


/** Open a zip file, path muth contain full path name */
zipFile unzipOpen(const char *path);

/** Close a ZipFile opened with unzipOpen.
 * If there is files inside the .zip opened with unzipOpenCurrentFile,
 * these files MUST be closed with unzipCloseCurrentFile before calling
 * unzipClose.
 * return ZIP_OK if there is no problem.
 */
int unzipClose(zipFile file);

/** Write info about the ZipFile in the *pglobal_info structure.
 * No preparation of the structure is needed.
 * return ZIP_OK if there is no problem.
 */
int unzipGetGlobalInfo(zipFile file, zip_global_info * pglobal_info);

/** Set the current file of the zipFile to the first file.
 * return ZIP_OK if there is no problem.
 */
int unzipGoToFirstFile(zipFile file);

/** Set the current file of the zipFile to the next file.
 * return ZIP_OK if there is no problem.
 * return ZIP_END_OF_LIST_OF_FILE if the actual file was the last.
 */
int unzipGoToNextFile(zipFile file);


/* Write info aout the ZipFile in the *pglobal_info structure.
 * No preparation of the structure is needed.
 * return ZIP_OK if there is no problem.
 */
int unzipGetCurrentFileInfo(zipFile file,
    zip_file_info * pfile_info,
    char * szFileName,
    unsigned long fileNameBufferSize,
    void * extraField,
    unsigned long extraFieldBufferSize,
    char * szComment,
    unsigned long commentBufferSize);

/** Open for reading data the current file in the ZipFile.
 * return ZIP_OK if there is no problem.
 */
int unzipOpenCurrentFile(zipFile file);

/** Close the file in zip opened with unzipOpenCurrentFile
 * return ZIP_CRCERROR if all the file was read but the CRC is not good
 */
int unzipCloseCurrentFile(zipFile file);

/**
  Read bytes from the current file.
  buf contain buffer where data must be copied
  len the size of buf.

  return the number of byte copied if somes bytes are copied
  return 0 if the end of file was reached
  return <0 with error code if there is an error
    (UNZ_ERRNO for IO error, or zLib error for uncompress error)
*/
int unzipReadCurrentFile ( zipFile file, void * buf, unsigned len);


#endif /* HAVE_ZLIB */

#endif /* __LIBWZD_SFV_ZIP_H__ */
