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

#include <stdlib.h>
#include <stdio.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#ifdef HAVE_ZLIB

#include <stdio.h>

#include "libwzd_sfv_zip.h"

typedef struct {
  unsigned long offset_curfile; /* relative offset of local header 4 bytes */
} zip_file_info_internal;

/* file_in_zip_read_info_s contain internal information about a file in zipfile,
 * when reading and decompress it
 */
typedef struct {
  char * read_buffer;                   /* internal buffer for compressed data */
  z_stream stream;                      /* zLib stream structure for inflate */

  unsigned long pos_in_zipfile;         /* position in byte on the zipfile, for fseek */
  unsigned long stream_initialised;     /* flag set if structure is initialised */

  unsigned long offset_local_extrafield; /* offset of the local extra field */
  unsigned int size_local_extrafield;   /* size of the local extrafield */
  unsigned long pos_local_extrafield;   /* position of the local extra field in read */

  unsigned long crc32;                  /* crc32 of all data uncompressed */
  unsigned long crc32_wait;             /* crc32 we must obtain after decompress all */
  unsigned long rest_read_compressed;   /* number of bytes to be decompressed */
  unsigned long rest_read_uncompressed; /* number of bytes to be obtained after decomp */
  FILE * file;                          /* io structure of the zipfile */
  unsigned long compression_method;     /* compression method (0==store) */
  unsigned long bytes_before_zipfile;   /* bytes before the zipfile (>0 for sfx) */
} file_in_zip_read_info_s;

typedef struct {
  FILE * file;                          /* io structure of the zipfile */
  zip_global_info gi;                   /* public global information */
  unsigned long bytes_before_zipfile;   /* bytes before the zipfile (>0 for sfx) */
  unsigned long num_file;               /* number of the current file in the zipfile */
  unsigned long pos_in_central_dir;     /* pos of the current file in the central dir */
  unsigned long current_file_ok;        /* flag about the usability of the current dir */
  unsigned long central_pos;            /* position of the beginning of the central dir */

  unsigned long size_central_dir;       /* size of the central directory */
  unsigned long offset_central_dir;     /* offset start of central directory with respect
                                         * to the starting disk number */
  zip_file_info cur_file_info;          /* public info about the current file in zip */
  zip_file_info_internal cur_file_info_internal;        /* private info about it */
  file_in_zip_read_info_s * pfile_in_zip_read; /* structure on the current file we are decompressing */
} zipFile_s;

#define ZIP_BUFSIZE             (16384)

#define ZIP_MAXFILENAMEINZIP    (256)

#define SIZECENTRALDIRITEM      (0x2e)
#define SIZEIPLOCALHEADER       (0x1e)



#define BUFREADCOMMENT  (0x400)

/* Locate the Central Directory of a zipfile (at the end, just before
 * the global comment)
 */
static unsigned long zipLocal_SearchCentralDir(FILE * fin)
{
  unsigned char * buf;
  unsigned long uSizeFile;
  unsigned long uBackRead;
  unsigned long uMaxBack=0xffff; /* maximum size of global comment */
  unsigned long uPosFound=0;

  if (fseek(fin,0,SEEK_END) != 0)
    return 0;

  uSizeFile = ftell(fin);

  if (uMaxBack > uSizeFile)
    uMaxBack = uSizeFile;

  buf = (unsigned char *)malloc(BUFREADCOMMENT+4);
  if (!buf)
    return 0;

  uBackRead = 4;
  while (uBackRead < uMaxBack)
  {
    unsigned long uReadSize, uReadPos;
    int i;

    if (uBackRead+BUFREADCOMMENT > uMaxBack)
      uBackRead = uMaxBack;
    else
      uBackRead += BUFREADCOMMENT;
    uReadPos = uSizeFile - uBackRead;

    uReadSize = ((BUFREADCOMMENT+4) < (uSizeFile-uReadPos)) ?
      (BUFREADCOMMENT+4) : (uSizeFile-uReadPos);
    if (fseek(fin,uReadPos,SEEK_SET)!=0)
      break;

    if (fread(buf,(unsigned int)uReadSize,1,fin)!=1)
      break;

    for (i=(int)uReadSize-3; (i--)>0; )
      if (((*(buf+i))==0x50) && ((*(buf+i+1))==0x4b) &&
          ((*(buf+i+2))==0x05) && ((*(buf+i+3))==0x06))
      {
        uPosFound = uReadPos + i;
        break;
      }

    if (uPosFound != 0)
      break;
  }

  free(buf);
  return uPosFound;
}

static int zipLocal_getByte(FILE *fin, int * pi)
{
  unsigned char c;
  int err = fread(&c, 1, 1, fin);
  if (err == 1)
  {
    *pi = (int)c;
    return ZIP_OK;
  }
  else
  {
    if (ferror(fin))
      return ZIP_ERRNO;
    else
      return ZIP_EOF;
  }
}

static int zipLocal_getShort(FILE *fin, unsigned long *pX)
{
  unsigned long x;
  int i;
  int err;

  err = zipLocal_getByte(fin,&i);
  x = (unsigned long)i;

  if (err == ZIP_OK)
    err = zipLocal_getByte(fin,&i);
  x += ((unsigned long)i) << 8;

  if (err == ZIP_OK)
    *pX = x;
  else
    *pX = 0;
  return err;
}

static int zipLocal_getLong(FILE *fin, unsigned long *pX)
{
  unsigned long x;
  int i;
  int err;

  err = zipLocal_getByte(fin,&i);
  x = (unsigned long)i;

  if (err == ZIP_OK)
    err = zipLocal_getByte(fin,&i);
  x += ((unsigned long)i) << 8;

  if (err == ZIP_OK)
    err = zipLocal_getByte(fin,&i);
  x += ((unsigned long)i) << 16;

  if (err == ZIP_OK)
    err = zipLocal_getByte(fin,&i);
  x += ((unsigned long)i) << 24;

  if (err == ZIP_OK)
    *pX = x;
  else
    *pX = 0;
  return err;
}


/* My own strcmpi / strcasecmp */
static int internal_strcasecmp (const char* fileName1, const char* fileName2)
{
  for (;;)
  {
    char c1=*(fileName1++);
    char c2=*(fileName2++);
    if ((c1>='a') && (c1<='z'))
      c1 -= 0x20;
    if ((c2>='a') && (c2<='z'))
      c2 -= 0x20;
    if (c1=='\0')
      return ((c2=='\0') ? 0 : -1);
    if (c2=='\0')
      return 1;
    if (c1<c2)
      return -1;
    if (c1>c2)
      return 1;
  }
}


#ifdef  CASESENSITIVITYDEFAULT_NO
#define CASESENSITIVITYDEFAULTVALUE 2
#else
#define CASESENSITIVITYDEFAULTVALUE 1
#endif

#ifndef FCT_STRCASECMP
#define FCT_STRCASECMP internal_strcasecmp
#endif

/* 
   Compare two filename (fileName1,fileName2).
   If iCaseSenisivity = 1, comparision is case sensitivity (like strcmp)
   If iCaseSenisivity = 2, comparision is not case sensitivity (like strcmpi
                                                                or strcasecmp)
   If iCaseSenisivity = 0, case sensitivity is defaut of your operating system
        (like 1 on Unix, 2 on Windows)

*/
int unzipStringFileNameCompare (const char* fileName1, const char* fileName2, int iCaseSensitivity)
{
  if (iCaseSensitivity==0)
    iCaseSensitivity=CASESENSITIVITYDEFAULTVALUE;

  if (iCaseSensitivity==1)
    return strcmp(fileName1,fileName2);

  return FCT_STRCASECMP(fileName1,fileName2);
} 








/** Open a zip file, path muth contain full path name */
zipFile unzipOpen(const char *path)
{
  zipFile_s us;
  zipFile_s *s;
  unsigned long central_pos, uL;
  FILE * fin;
  unsigned long number_disk; /* number of the current disk, used for spanning zip, unsupported, always 0 */
  unsigned long number_disk_with_CD; /* number of the disk with central dir, used for spanning zip, unsupported, always 0 */
  unsigned long number_entry_CD; /* total number of entries in the central dir (same than number_entry on nospan) */
  int err=ZIP_OK;

  fin = fopen(path,"rb");
  if (!fin)
    return NULL;

  central_pos = zipLocal_SearchCentralDir(fin);
  if (central_pos == 0)
    err = ZIP_ERRNO;

  if (fseek(fin,central_pos,SEEK_SET) != 0)
    err = ZIP_ERRNO;

  /* the signature, already checked */
  if (zipLocal_getLong(fin,&uL) != ZIP_OK)
    err = ZIP_ERRNO;

  /* number of this disk */
  if (zipLocal_getShort(fin,&number_disk) != ZIP_OK)
    err = ZIP_ERRNO;

  /* number of this disk with the start of the central directory */
  if (zipLocal_getShort(fin,&number_disk_with_CD) != ZIP_OK)
    err = ZIP_ERRNO;

  /* total number of entries in the central dir on this disk */
  if (zipLocal_getShort(fin,&us.gi.number_entry) != ZIP_OK)
    err = ZIP_ERRNO;

  /* total number of entries in the central dir */
  if (zipLocal_getShort(fin,&number_entry_CD) != ZIP_OK)
    err = ZIP_ERRNO;

  if ((number_entry_CD != us.gi.number_entry) ||
      (number_disk_with_CD != 0) ||
      (number_disk != 0))
    err = ZIP_BADZIPFILE;

  /* size of the central directory */
  if (zipLocal_getLong(fin,&us.size_central_dir) != ZIP_OK)
    err = ZIP_ERRNO;

  /* offset of start of central directory with respect to the starting disk number */
  if (zipLocal_getLong(fin,&us.offset_central_dir) != ZIP_OK)
    err = ZIP_ERRNO;

  /* zipfile comment length */
  if (zipLocal_getShort(fin,&us.gi.size_comment) != ZIP_OK)
    err = ZIP_ERRNO;

  if ((central_pos < us.offset_central_dir + us.size_central_dir) &&
      (err == ZIP_OK))
    err = ZIP_BADZIPFILE;

  if (err != ZIP_OK)
  {
    fclose(fin);
    return NULL;
  }

  us.file = fin;
  us.bytes_before_zipfile = central_pos - (us.offset_central_dir + us.size_central_dir);
  us.central_pos = central_pos;
  us.pfile_in_zip_read = NULL;

  s = (zipFile_s*)malloc(sizeof(zipFile_s));
  *s = us;
  unzipGoToFirstFile((zipFile)s);

  return (zipFile)s;
}

/* Close a ZipFile opened with zipOpen.
 * If there are files inside the .zip opened with unzipOpenCurrentFile,
 * these files MUST be closed with unzipCloseCurrentFile before calling
 * unzipClose.
 * return ZIP_OK if no problem.
 */
int unzipClose(zipFile file)
{
  zipFile_s * s;

  if (!file)
    return ZIP_PARAMETERERROR;
  s = (zipFile_s*)file;

  if (s->pfile_in_zip_read != NULL)
    unzipCloseCurrentFile(file);

  fclose(s->file);
  free(s);
  return ZIP_OK;
}

/* Write info about the ZipFile in the *pglobal_info structure.
 * No preparation of the structure is needed.
 * return ZIP_OK if there is no problem.
 */
int unzipGetGlobalInfo(zipFile file, zip_global_info * pglobal_info)
{
  zipFile_s * s;
  if (!file)
    return ZIP_PARAMETERERROR;
  s = (zipFile_s*)file;
  *pglobal_info = s->gi;
  return ZIP_OK;
}

/* Translate date/time from DOS format to tm_zip (more easily readable) */
static void unzipLocal_DosDateToTmuDate(unsigned long DosDate,
    tm_zip * ptm)
{
  unsigned long date;
  date = (unsigned long)(DosDate >> 16);
  ptm->tm_mday = (unsigned int)(date & 0x01f);
  ptm->tm_mon = (unsigned int)((((date) & 0x1e0)/0x20)-1);
  ptm->tm_year = (unsigned int)(((date & 0x0fe00)/0x200)+1980);

  ptm->tm_hour = (unsigned int)((DosDate & 0xf800)/0x800);
  ptm->tm_min = (unsigned int)((DosDate & 0x7e0)/0x20);
  ptm->tm_sec = (unsigned int)(2*(DosDate & 0x1f));
}

/* Get Info about the current file in the zipfile, with internal info only */
static int unzipLocal_GetCurrentFileInfoInternal(zipFile file,
    zip_file_info * pfile_info,
    zip_file_info_internal * pfile_info_internal,
    char * szFileName,
    unsigned long fileNameBufferSize,
    void * extraField,
    unsigned long extraFieldBufferSize,
    char * szComment,
    unsigned long commentBufferSize)
{
  zipFile_s * s;
  zip_file_info file_info;
  zip_file_info_internal file_info_internal;
  int err=ZIP_OK;
  unsigned long magic;
  long lseek=0;

  if (!file)
    return ZIP_PARAMETERERROR;
  s = (zipFile_s*)file;
  if (fseek(s->file,s->pos_in_central_dir+s->bytes_before_zipfile,SEEK_SET) != 0)
    err = ZIP_ERRNO;

  /* check the magic */
  if (err == ZIP_OK)
    if (zipLocal_getLong(s->file,&magic) != ZIP_OK)
      err = ZIP_ERRNO;
    else if (magic != 0x02014b50)
      err = ZIP_BADZIPFILE;

  if (zipLocal_getShort(s->file,&file_info.version) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.version_needed) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.flag) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.compression_method) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&file_info.dosDate) != ZIP_OK)
    err = ZIP_ERRNO;
  unzipLocal_DosDateToTmuDate(file_info.dosDate,&file_info.tmu_date);

  if (zipLocal_getLong(s->file,&file_info.crc) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&file_info.compressed_size) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&file_info.uncompressed_size) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.size_filename) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.size_file_extra) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.size_file_comment) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.disk_num_start) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&file_info.internal_fa) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&file_info.external_fa) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&file_info_internal.offset_curfile) != ZIP_OK)
    err = ZIP_ERRNO;

  lseek += file_info.size_filename;
  if ((err==ZIP_OK) && (szFileName!=NULL))
  {
    unsigned long uSizeRead;
    if (file_info.size_filename < fileNameBufferSize)
    {
      *(szFileName+file_info.size_filename) = '\0';
      uSizeRead = file_info.size_filename;
    }
    else
      uSizeRead = fileNameBufferSize;

    if ((file_info.size_filename>0) && (fileNameBufferSize>0))
      if (fread(szFileName,(unsigned int)uSizeRead,1,s->file) != 1)
        err = ZIP_ERRNO;
    lseek -= uSizeRead;
  }

  if ((err==ZIP_OK) && (extraField!=NULL))
  {
    unsigned long uSizeRead;
    if (file_info.size_file_extra < extraFieldBufferSize)
      uSizeRead = file_info.size_file_extra;
    else
      uSizeRead = extraFieldBufferSize;

    if (lseek != 0)
      if (fseek(s->file,lseek,SEEK_CUR) == 0)
        lseek = 0;
      else
        err = ZIP_ERRNO;

    if ((file_info.size_file_extra>0) && (extraFieldBufferSize>0))
      if (fread(extraField,(unsigned int)uSizeRead,1,s->file) != 1)
        err = ZIP_ERRNO;
    lseek += file_info.size_file_extra - uSizeRead;
  }
  else
    lseek += file_info.size_file_extra;

  if ((err==ZIP_OK) && (szComment!=NULL))
  {
    unsigned long uSizeRead;
    if (file_info.size_file_comment < commentBufferSize)
    {
      *(szComment+file_info.size_file_comment) = '\0';
      uSizeRead = file_info.size_file_comment;
    }
    else
      uSizeRead = commentBufferSize;

    if (lseek != 0)
      if (fseek(s->file,lseek,SEEK_CUR) == 0)
        lseek = 0;
      else
        err = ZIP_ERRNO;

    if ((file_info.size_file_comment>0) && (commentBufferSize>0))
      if (fread(szComment,(unsigned int)uSizeRead,1,s->file) != 1)
        err = ZIP_ERRNO;
    lseek += file_info.size_file_comment - uSizeRead;
  }
  else
    lseek += file_info.size_file_comment;

  if ((err==ZIP_OK) && (pfile_info!=NULL))
    *pfile_info=file_info;

  if ((err==ZIP_OK) && (pfile_info_internal!=NULL))
    *pfile_info_internal=file_info_internal;

  return err;
}

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
    unsigned long commentBufferSize)
{
  return unzipLocal_GetCurrentFileInfoInternal(file,pfile_info,NULL,
      szFileName,fileNameBufferSize,
      extraField,extraFieldBufferSize,
      szComment,commentBufferSize);
}

/* Set the current file of the zipfile to the first file.
 * return ZIP_OK if there is no problem.
 */
int unzipGoToFirstFile(zipFile file)
{
  int err=ZIP_OK;
  zipFile_s * s;

  if (!file)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  s->pos_in_central_dir=s->offset_central_dir;
  s->num_file=0;
  err=unzipLocal_GetCurrentFileInfoInternal(file,&s->cur_file_info,
      &s->cur_file_info_internal,
      NULL, 0, NULL, 0, NULL, 0);
  s->current_file_ok = (err == ZIP_OK);

  return err;
}

/* Set the current file of the zipfile to the next file.
 * return ZIP_OK if there is no problem.
 * return ZIP_END_OF_LIST_OF_FILE if the actual file was the last.
 */
int unzipGoToNextFile(zipFile file)
{
  int err=ZIP_OK;
  zipFile_s * s;

  if (!file)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  if (!s->current_file_ok)
    return ZIP_END_OF_LIST_OF_FILE;
  if (!s->num_file+1 == s->gi.number_entry)
    return ZIP_END_OF_LIST_OF_FILE;
  
  s->pos_in_central_dir += SIZECENTRALDIRITEM + s->cur_file_info.size_filename +
    s->cur_file_info.size_file_extra + s->cur_file_info.size_file_comment;
  s->num_file++;
  err = unzipLocal_GetCurrentFileInfoInternal(file,&s->cur_file_info,
      &s->cur_file_info_internal,
      NULL,0,NULL,0,NULL,0);
  s->current_file_ok = (err == ZIP_OK);

  return err;
}





/*
  Try locate the file szFileName in the zipfile.
  For the iCaseSensitivity signification, see unzipStringFileNameCompare

  return value :
  UNZ_OK if the file is found. It becomes the current file.
  UNZ_END_OF_LIST_OF_FILE if the file is not found
*/
extern int unzLocateFile (zipFile file, const char *szFileName, int iCaseSensitivity)
{
  zipFile_s * s;
  int err;

  unsigned long num_fileSaved;
  unsigned long pos_in_central_dirSaved;


  if (file==NULL)
    return ZIP_PARAMETERERROR;

  if (strlen(szFileName)>=ZIP_MAXFILENAMEINZIP)
    return ZIP_PARAMETERERROR;

  s=(zipFile_s*)file;
  if (!s->current_file_ok)
    return ZIP_END_OF_LIST_OF_FILE;

  num_fileSaved = s->num_file;
  pos_in_central_dirSaved = s->pos_in_central_dir;

  err = unzipGoToFirstFile(file);

  while (err == ZIP_OK)
  {
    char szCurrentFileName[ZIP_MAXFILENAMEINZIP+1];
    unzipGetCurrentFileInfo(file,NULL,
        szCurrentFileName,sizeof(szCurrentFileName)-1,
        NULL,0,NULL,0);
    if (unzipStringFileNameCompare(szCurrentFileName,
          szFileName,iCaseSensitivity)==0)
      return ZIP_OK;
    err = unzipGoToNextFile(file);
  }

  s->num_file = num_fileSaved ;
  s->pos_in_central_dir = pos_in_central_dirSaved ;
  return err;
}



/* Read the local header of the current ZipFile.
 * Check the coherency of the local header and info at the end of the
 * central directory about this file.
 * store in *piSizeVar the size of the extra info in local header
 *  (filename and size of extra field data).
 */
static int unzipLocal_CheckCurrentFileHeaderCoherency(zipFile_s * s,
    unsigned int * piSizeVar,
    unsigned long * poffset_local_extrafield,
    unsigned int * psize_local_extrafield)
{
  unsigned long magic, data, flags;
  unsigned long size_filename;
  unsigned long size_extra_field;
  int err=ZIP_OK;

  *piSizeVar = 0;
  *poffset_local_extrafield = 0;
  *psize_local_extrafield = 0;

  if (fseek(s->file,s->cur_file_info_internal.offset_curfile + s->bytes_before_zipfile,SEEK_SET) != 0)
    return ZIP_ERRNO;

  if (err == ZIP_OK)
    if (zipLocal_getLong(s->file,&magic) != ZIP_OK)
      err = ZIP_ERRNO;
    else if (magic != 0x04034b50)
      err = ZIP_BADZIPFILE;

  if (zipLocal_getShort(s->file,&data) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&flags) != ZIP_OK)
    err = ZIP_ERRNO;

  if (zipLocal_getShort(s->file,&data) != ZIP_OK)
    err = ZIP_ERRNO;
  else if ((err==ZIP_OK) && (data != s->cur_file_info.compression_method))
    err = ZIP_BADZIPFILE;

  if ((err==ZIP_OK) && (s->cur_file_info.compression_method!=0) &&
      (s->cur_file_info.compression_method!=Z_DEFLATED))
    err = ZIP_BADZIPFILE;

  if (zipLocal_getLong(s->file,&data) != ZIP_OK) /* date/time */
    err = ZIP_ERRNO;

  if (zipLocal_getLong(s->file,&data) != ZIP_OK) /* crc */
    err = ZIP_ERRNO;
  else if ((err==ZIP_OK) && (data!=s->cur_file_info.crc) && ((flags & 8)==0))
    err = ZIP_BADZIPFILE;

  if (zipLocal_getLong(s->file,&data) != ZIP_OK) /* compressed size */
    err = ZIP_ERRNO;
  else if ((err==ZIP_OK) && (data!=s->cur_file_info.compressed_size) && ((flags & 8)==0))
    err = ZIP_BADZIPFILE;

  if (zipLocal_getLong(s->file,&data) != ZIP_OK) /* uncompressed size */
    err = ZIP_ERRNO;
  else if ((err==ZIP_OK) && (data!=s->cur_file_info.uncompressed_size) && ((flags & 8)==0))
    err = ZIP_BADZIPFILE;

  if (zipLocal_getShort(s->file,&size_filename) != ZIP_OK)
    err = ZIP_ERRNO;
  else if ((err==ZIP_OK) && (size_filename!=s->cur_file_info.size_filename))
    err = ZIP_BADZIPFILE;

  *piSizeVar += (unsigned int)size_filename;
  
  if (zipLocal_getShort(s->file,&size_extra_field) != ZIP_OK)
    err = ZIP_ERRNO;
  *poffset_local_extrafield = s->cur_file_info_internal.offset_curfile + SIZEIPLOCALHEADER + size_filename;
  *psize_local_extrafield = (unsigned int)size_extra_field;

  *piSizeVar += (unsigned int)size_extra_field;

  return err;
}

/** Open for reading data the current file in the ZipFile.
 * return ZIP_OK if there is no problem.
 */
int unzipOpenCurrentFile(zipFile file)
{
  int err=ZIP_OK;
  int store;
  zipFile_s * s;
  unsigned int iSizeVar;
  file_in_zip_read_info_s * pfile_in_zip_read_info;
  unsigned long offset_local_extrafield;
  unsigned int size_local_extrafield;

  if (!file)
    return ZIP_PARAMETERERROR;
  s = (zipFile_s*)file;
  if (!s->current_file_ok)
    return ZIP_PARAMETERERROR;

  if (unzipLocal_CheckCurrentFileHeaderCoherency(s,&iSizeVar,
        &offset_local_extrafield,&size_local_extrafield) != ZIP_OK)
    return ZIP_BADZIPFILE;

  pfile_in_zip_read_info =(file_in_zip_read_info_s*)malloc(sizeof(file_in_zip_read_info_s));
  if (!pfile_in_zip_read_info)
    return ZIP_INTERNALERROR;

  pfile_in_zip_read_info->read_buffer = (char*)malloc(ZIP_BUFSIZE);
  pfile_in_zip_read_info->offset_local_extrafield = offset_local_extrafield;
  pfile_in_zip_read_info->size_local_extrafield = size_local_extrafield;
  pfile_in_zip_read_info->pos_local_extrafield = 0;

  if (!pfile_in_zip_read_info->read_buffer)
  {
    free(pfile_in_zip_read_info);
    return ZIP_INTERNALERROR;
  }

  pfile_in_zip_read_info->stream_initialised = 0;

  if ((s->cur_file_info.compression_method!=0) &&
      (s->cur_file_info.compression_method!=Z_DEFLATED))
    err = ZIP_BADZIPFILE;
  store = (s->cur_file_info.compression_method==0);

  pfile_in_zip_read_info->crc32_wait = s->cur_file_info.crc;
  pfile_in_zip_read_info->crc32 = 0;
  pfile_in_zip_read_info->compression_method = s->cur_file_info.compression_method;
  pfile_in_zip_read_info->file = s->file;
  pfile_in_zip_read_info->bytes_before_zipfile = s->bytes_before_zipfile;

  pfile_in_zip_read_info->stream.total_out = 0;

  if (!store)
  {
    pfile_in_zip_read_info->stream.zalloc = (alloc_func)0;
    pfile_in_zip_read_info->stream.zfree = (free_func)0;
    pfile_in_zip_read_info->stream.opaque = (voidpf)0;

    err = inflateInit2(&pfile_in_zip_read_info->stream, -MAX_WBITS);
    if (err == Z_OK)
      pfile_in_zip_read_info->stream_initialised = 1;
    /* windowBits is passed < 0 to tell that there is no zlib header.
     * Note that in this case inflate *requires* an extra "dummy" byte
     * after the compressed stream in order to complete decompression and
     * return Z_STREAM_END.
     * In unzip, I don't wait absolutely Z_STREAM_END because I know the size
     * of both compressed and uncompressed data.
     */
  }
  pfile_in_zip_read_info->rest_read_compressed = s->cur_file_info.compressed_size;
  pfile_in_zip_read_info->rest_read_uncompressed = s->cur_file_info.uncompressed_size;

  pfile_in_zip_read_info->pos_in_zipfile = s->cur_file_info_internal.offset_curfile + SIZEIPLOCALHEADER + iSizeVar;

  pfile_in_zip_read_info->stream.avail_in = (unsigned int)0;

  s->pfile_in_zip_read = pfile_in_zip_read_info;

  return ZIP_OK;
}

/*
  Read bytes from the current file.
  buf contain buffer where data must be copied
  len the size of buf.

  return the number of byte copied if somes bytes are copied
  return 0 if the end of file was reached
  return <0 with error code if there is an error
    (UNZ_ERRNO for IO error, or zLib error for uncompress error)
*/
int unzipReadCurrentFile ( zipFile file, void * buf, unsigned len)
{
  int err=ZIP_OK;
  unsigned int iRead = 0;
  zipFile_s * s;
  file_in_zip_read_info_s* pfile_in_zip_read_info;
  if (file==NULL)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  pfile_in_zip_read_info=s->pfile_in_zip_read;

  if (pfile_in_zip_read_info==NULL)
    return ZIP_PARAMETERERROR;

  if ((pfile_in_zip_read_info->read_buffer == NULL))
    return ZIP_END_OF_LIST_OF_FILE;
  if (len==0)
    return 0;

  pfile_in_zip_read_info->stream.next_out = (unsigned char*)buf;

  pfile_in_zip_read_info->stream.avail_out = (unsigned int)len;
	
  if (len>pfile_in_zip_read_info->rest_read_uncompressed)
    pfile_in_zip_read_info->stream.avail_out = 
      (unsigned int)pfile_in_zip_read_info->rest_read_uncompressed;

  while (pfile_in_zip_read_info->stream.avail_out>0)
  {
    if ((pfile_in_zip_read_info->stream.avail_in==0) &&
        (pfile_in_zip_read_info->rest_read_compressed>0))
    {
      unsigned int uReadThis = ZIP_BUFSIZE;
      if (pfile_in_zip_read_info->rest_read_compressed<uReadThis)
        uReadThis = (unsigned int)pfile_in_zip_read_info->rest_read_compressed;
      if (uReadThis == 0)
        return ZIP_EOF;
      if (fseek(pfile_in_zip_read_info->file,
            pfile_in_zip_read_info->pos_in_zipfile + 
            pfile_in_zip_read_info->bytes_before_zipfile,SEEK_SET)!=0)
        return ZIP_ERRNO;
      if (fread(pfile_in_zip_read_info->read_buffer,uReadThis,1,
            pfile_in_zip_read_info->file)!=1)
        return ZIP_ERRNO;
      pfile_in_zip_read_info->pos_in_zipfile += uReadThis;

      pfile_in_zip_read_info->rest_read_compressed-=uReadThis;
			
      pfile_in_zip_read_info->stream.next_in = 
        (unsigned char*)pfile_in_zip_read_info->read_buffer;
      pfile_in_zip_read_info->stream.avail_in = (unsigned int)uReadThis;
    }

    if (pfile_in_zip_read_info->compression_method==0)
    {
      unsigned int uDoCopy,i ;
      if (pfile_in_zip_read_info->stream.avail_out < 
          pfile_in_zip_read_info->stream.avail_in)
        uDoCopy = pfile_in_zip_read_info->stream.avail_out ;
      else
        uDoCopy = pfile_in_zip_read_info->stream.avail_in ;

      for (i=0;i<uDoCopy;i++)
        *(pfile_in_zip_read_info->stream.next_out+i) =
          *(pfile_in_zip_read_info->stream.next_in+i);

      pfile_in_zip_read_info->crc32 = crc32(pfile_in_zip_read_info->crc32,
          pfile_in_zip_read_info->stream.next_out,
          uDoCopy);
      pfile_in_zip_read_info->rest_read_uncompressed-=uDoCopy;
      pfile_in_zip_read_info->stream.avail_in -= uDoCopy;
      pfile_in_zip_read_info->stream.avail_out -= uDoCopy;
      pfile_in_zip_read_info->stream.next_out += uDoCopy;
      pfile_in_zip_read_info->stream.next_in += uDoCopy;
      pfile_in_zip_read_info->stream.total_out += uDoCopy;
      iRead += uDoCopy;
    }
    else
    {
      unsigned long uTotalOutBefore,uTotalOutAfter;
      const unsigned char *bufBefore;
      unsigned long uOutThis;
      int flush=Z_SYNC_FLUSH;

      uTotalOutBefore = pfile_in_zip_read_info->stream.total_out;
      bufBefore = pfile_in_zip_read_info->stream.next_out;

      /*
         if ((pfile_in_zip_read_info->rest_read_uncompressed ==
         pfile_in_zip_read_info->stream.avail_out) &&
         (pfile_in_zip_read_info->rest_read_compressed == 0))
         flush = Z_FINISH;
         */
      err=inflate(&pfile_in_zip_read_info->stream,flush);

      uTotalOutAfter = pfile_in_zip_read_info->stream.total_out;
      uOutThis = uTotalOutAfter-uTotalOutBefore;
			
      pfile_in_zip_read_info->crc32 = 
        crc32(pfile_in_zip_read_info->crc32,bufBefore,
            (unsigned int)(uOutThis));

      pfile_in_zip_read_info->rest_read_uncompressed -= uOutThis;

      iRead += (unsigned int)(uTotalOutAfter - uTotalOutBefore);

      if (err==Z_STREAM_END)
        return (iRead==0) ? ZIP_EOF : iRead;
      if (err!=Z_OK) 
        break;
    }
  }

  if (err==Z_OK)
    return iRead;
  return err;
}


/*
  Give the current position in uncompressed data
*/
z_off_t unzipTell (zipFile file)
{
  zipFile_s * s;
  file_in_zip_read_info_s* pfile_in_zip_read_info;
  if (file==NULL)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  pfile_in_zip_read_info=s->pfile_in_zip_read;

  if (pfile_in_zip_read_info==NULL)
    return ZIP_PARAMETERERROR;

  return (z_off_t)pfile_in_zip_read_info->stream.total_out;
}


/*
  return 1 if the end of file was reached, 0 elsewhere 
*/
int unzipEof (zipFile file)
{
  zipFile_s * s;
  file_in_zip_read_info_s* pfile_in_zip_read_info;
  if (file==NULL)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  pfile_in_zip_read_info=s->pfile_in_zip_read;

  if (pfile_in_zip_read_info==NULL)
    return ZIP_PARAMETERERROR;
	
  if (pfile_in_zip_read_info->rest_read_uncompressed == 0)
    return 1;
  else
    return 0;
}


/*
  Read extra field from the current file (opened by unzOpenCurrentFile)
  This is the local-header version of the extra field (sometimes, there is
    more info in the local-header version than in the central-header)

  if buf==NULL, it return the size of the local extra field that can be read

  if buf!=NULL, len is the size of the buffer, the extra header is copied in buf.
  the return value is the number of bytes copied in buf, or (if <0) the error code
*/
int unzipGetLocalExtrafield ( zipFile file, void * buf, unsigned len)
{
  zipFile_s * s;
  file_in_zip_read_info_s* pfile_in_zip_read_info;
  unsigned int read_now;
  unsigned long size_to_read;

  if (!file)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;
  pfile_in_zip_read_info=s->pfile_in_zip_read;

  if (!pfile_in_zip_read_info)
    return ZIP_PARAMETERERROR;

  size_to_read = (pfile_in_zip_read_info->size_local_extrafield - 
      pfile_in_zip_read_info->pos_local_extrafield);

  if (!buf)
    return (int)size_to_read;

  if (len>size_to_read)
    read_now = (unsigned int)size_to_read;
  else
    read_now = (unsigned int)len ;

  if (read_now==0)
    return 0;

  if (fseek(pfile_in_zip_read_info->file,
        pfile_in_zip_read_info->offset_local_extrafield + 
        pfile_in_zip_read_info->pos_local_extrafield,SEEK_SET)!=0)
    return ZIP_ERRNO;

  if (fread(buf,(unsigned int)size_to_read,1,pfile_in_zip_read_info->file)!=1)
    return ZIP_ERRNO;

  return (int)read_now;
}

/* Close the file in zip opened with unzipOpenCurrentFile
 * return ZIP_CRCERROR if all the file was read but the CRC is not good
 */
int unzipCloseCurrentFile(zipFile file)
{
  int err=ZIP_OK;

  zipFile_s *s;
  file_in_zip_read_info_s * pfile_in_zip_read_info;
  if (file == NULL)
    return ZIP_PARAMETERERROR;
  s = (zipFile_s*)file;
  pfile_in_zip_read_info=s->pfile_in_zip_read;

  if (pfile_in_zip_read_info->rest_read_uncompressed == 0)
  {
    if (pfile_in_zip_read_info->crc32 != pfile_in_zip_read_info->crc32_wait)
      err = ZIP_CRCERROR;
  }

  free(pfile_in_zip_read_info->read_buffer);
  pfile_in_zip_read_info->read_buffer = NULL;
  if (pfile_in_zip_read_info->stream_initialised)
    inflateEnd(&pfile_in_zip_read_info->stream);

  pfile_in_zip_read_info->stream_initialised = 0;
  free(pfile_in_zip_read_info);

  s->pfile_in_zip_read = NULL;

  return err;
}

/*
  Get the global comment string of the ZipFile, in the szComment buffer.
  uSizeBuf is the size of the szComment buffer.
  return the number of byte copied or an error code <0
*/
int unzipGetGlobalComment ( zipFile file, char *szComment, unsigned long uSizeBuf)
{
  int err=ZIP_OK;
  zipFile_s * s;
  unsigned long uReadThis ;
  if (!file)
    return ZIP_PARAMETERERROR;
  s=(zipFile_s*)file;

  uReadThis = uSizeBuf;
  if (uReadThis>s->gi.size_comment)
    uReadThis = s->gi.size_comment;

  if (fseek(s->file,s->central_pos+22,SEEK_SET)!=0)
    return ZIP_ERRNO;

  if (uReadThis>0)
  {
    *szComment='\0';
    if (fread(szComment,(unsigned int)uReadThis,1,s->file)!=1)
      return ZIP_ERRNO;
  }

  if ((szComment != NULL) && (uSizeBuf > s->gi.size_comment))
    *(szComment+s->gi.size_comment)='\0';
  return (int)uReadThis;
}


#endif /* HAVE_ZLIB */
