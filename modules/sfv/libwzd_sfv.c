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

#include <dirent.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <wzd.h>

#define	incomplete_indicator	"../(incomplete)-%0"

#define	progressmeter		"[WzD] - %3.0d%% Complete - [WzD]"
#define	del_progressmeter	"\\[.*] - ...% Complete - \\[WzD]"

#define	other_completebar	"[WzD] - ( %.0mM %fF - COMPLETE ) - [WzD]"


#define BUFFER_LEN      4096

/* CRC lookup table */
static unsigned long crcs[256]={ 0x00000000,0x77073096,0xEE0E612C,0x990951BA,
0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,
0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,
0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,
0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,
0xA50AB56B,0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,
0xDCD60DCF,0xABD13D59,0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,
0x56B3C423,0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,
0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,
0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,
0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,
0xFBD44C65,0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,
0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,
0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,
0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,
0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,
0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,
0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,
0x6E6B06E7,0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,
0x17B7BE43,0x60B08ED5,0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,
0xA6BC5767,0x3FB506DD,0x48B2364B,0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,
0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,
0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,
0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,
0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,
0x0BDBDF21,0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,
0x6FB077E1,0x18B74777,0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,
0xF862AE69,0x616BFFD3,0x166CCF45,0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,
0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,
0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,
0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,
0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D};

/* Converts cookies in incomplete indicators */
char *c_incomplete(char *instr, char *path);

/* updates complete bar (erasing preceding one if existing) */
void sfv_update_completebar(wzd_sfv_file sfv, const char *filename, wzd_context_t *context);

/* parse dir to calculate release completion % */
float _sfv_get_release_percent(const char *dir, wzd_sfv_file sfv);

/* Calculates the 32-bit checksum of fname, and stores the result
 * in crc. Returns 0 on success, nonzero on error.
 */
int calc_crc32( const char *fname, unsigned long *crc ) {
    FILE *in;           /* input file */
    unsigned char buf[BUFSIZ]; /* pointer to the input buffer */
    size_t i, j;        /* buffer positions*/
    int k;              /* generic integer */
    unsigned long tmpcrc=0xFFFFFFFF;

    /* open file */
    if((in = fopen(fname, "rb")) == NULL) return -1;

    /* loop through the file and calculate CRC */
    while( (i=fread(buf, 1, BUFSIZ, in)) != 0 ){
        for(j=0; j<i; j++){
            k=(tmpcrc ^ buf[j]) & 0x000000FFL;
            tmpcrc=((tmpcrc >> 8) & 0x00FFFFFFL) ^ crcs[k];
        }
    }
    fclose(in);
    *crc=~tmpcrc; /* postconditioning */
    return 0;
}

/* inits an sfv struct
 */
void sfv_init(wzd_sfv_file *sfv)
{
  sfv->comments = NULL;
  sfv->sfv_list = NULL;
}

/* create / remove ".missing" / ".bad" depending on the result of the test
 */
int sfv_check_create(const char *filename, wzd_sfv_entry * entry)
{
  char missing[1024], bad[1024];
  unsigned long real_crc;
  int ret, fd;
  struct stat s;

  if (strlen(filename) > 1000) return -1;
  strcpy(missing,filename);
  strcpy(bad,filename);
  strcat(missing,".missing");
  strcat(bad,".bad");

  if (stat(filename,&s) && errno==ENOENT) {
    /* missing */
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(bad,&s)) { unlink(bad); }
    entry->state = SFV_MISSING;
    return 0;
  }
  if (s.st_size == 0) {
    /* remove 0-sized file and treat it as missing */
    unlink(filename);
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(bad,&s)) { unlink(bad); }
    entry->state = SFV_MISSING;
    return 0;
  }
  entry->size = s.st_size;
  ret = calc_crc32(filename,&real_crc);
  if (ret) return -1;

  if (real_crc == entry->crc) {
    if (!stat(bad,&s)) { unlink(bad); }
    if (!stat(missing,&s)) { unlink(missing); }
    entry->state = SFV_OK;
  } else { /* CRC differs */
    entry->state = SFV_BAD;
    fd = open(bad,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(missing,&s)) { unlink(missing); }
  }
  return 0;
}

/* frees contents of a sfv structure
 * if sfv was allocated on heap you MUST free sfv struct after
 */
void sfv_free(wzd_sfv_file *sfv)
{
  int i;

  i=0;
  if (sfv->comments) {
    while (sfv->comments[i])
    {
      free(sfv->comments[i]);
      sfv->comments[i] = NULL;
      i++;
    }
  }
  i=0;
  if (sfv->sfv_list) {
    while (sfv->sfv_list[i])
    {
      free(sfv->sfv_list[i]->filename);
      sfv->sfv_list[i]->filename = NULL;
      free(sfv->sfv_list[i]);
      sfv->sfv_list[i] = NULL;
      i++;
    }
  }
}

/* reads sfv file
 */
int sfv_read(const char *filename, wzd_sfv_file *sfv)
{
  FILE *in;
  struct stat st;
  char buf[BUFSIZ];
  char * ptr;
  char *err_ptr;
/*  size_t i;*/
  int count_comments=0, count_entries=0;
  int length;

  if (stat(filename,&st) < 0) return -1;
  if (!S_ISREG(st.st_mode)) return -1;
  if ((in=fopen(filename,"r")) == NULL) return -1;

  sfv->comments = malloc(50*sizeof(char*));
  sfv->sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  while ( fgets(buf,BUFSIZ-1,in) != NULL) {
/*    if (i == -1) return -1;*/
    ptr = buf;
    length = strlen(buf); /* fgets put a '\0' at the end */
    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    if (length <= 0) continue;
    /* XXX limitation */
    if (length > 512) continue;
    if (buf[0] == ';') { /* comment */
      /* count_comments + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_comments + 2 )% 50 == 0)
        sfv->comments = realloc(sfv->comments,(count_comments+50)*sizeof(char*));
      sfv->comments[count_comments] = malloc(length+1);
      strcpy(sfv->comments[count_comments],buf);
      count_comments++;
    } /* comment */
    else { /* entries */
      /* count_entries + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_entries + 2 )% 50 == 0)
        sfv->sfv_list = realloc(sfv->sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));
      if (length < 10) continue;
      ptr = buf + length - 8;
      *(buf+length-9) = '\0';
      sfv->sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
      sfv->sfv_list[count_entries]->crc = strtoul(ptr,&err_ptr, 16);
      if (*err_ptr != '\0') {
        free(sfv->sfv_list[count_entries]);
        continue;
      }
      sfv->sfv_list[count_entries]->filename = malloc(strlen(buf)+1);
      strcpy(sfv->sfv_list[count_entries]->filename,buf);
      sfv->sfv_list[count_entries]->state = SFV_UNKNOWN;
      sfv->sfv_list[count_entries]->size = 0;
      count_entries++;
    }
  }
  sfv->comments[count_comments] = NULL;
  sfv->sfv_list[count_entries] = NULL;

  return 0;
}

/* creates sfv file
 * returns 0 if all ok
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_create(const char * sfv_file)
{
  int ret=0, thisret;
  char * ptr;
  char directory[1024];
  char filename[2048];
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;
  DIR *dir;
  struct dirent *entr;
  int count_comments=0, count_entries=0;

  sfv_init(&sfv);

  sfv.comments = malloc(50*sizeof(char*));
  sfv.sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(directory,sfv_file,1023);
  ptr = strrchr(directory,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  strcpy(filename,directory);
  if ((dir=opendir(directory))==NULL) return -1;

  while ((entr=readdir(dir))!=NULL) {
    if (entr->d_name[0]=='.') continue;
    /* TODO check that file matches mask */

    if (strlen(entr->d_name)>4) {
      char extension[5];
      strcpy(extension,entr->d_name+strlen(entr->d_name)-4);
      /* files that should not be in a sfv */
      if (strcasecmp(extension,".nfo")==0 ||
	  strcasecmp(extension,".diz")==0 ||
	  strcasecmp(extension,".sfv")==0 ||
	  strcasecmp(extension,".txt")==0)
	continue;
    }
    /* add to sfv file */
    strcpy(filename,directory);
    ptr = filename + strlen(directory);
/*    strcpy(ptr,sfv.sfv_list[i]->filename);*/
    strcpy(ptr,entr->d_name);
    if (stat(filename,&s) || S_ISDIR(s.st_mode)) { continue; }
    thisret = calc_crc32(filename,&crc);
    /* count_entries + 2 : +1 for the new line to add, +1 to terminate
       array by NULL */
    if ((count_entries + 2 )% 50 == 0)
      sfv.sfv_list = realloc(sfv.sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));
    sfv.sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
    sfv.sfv_list[count_entries]->crc = crc;
    sfv.sfv_list[count_entries]->filename = strdup(entr->d_name);
    sfv.sfv_list[count_entries]->state = SFV_OK;
    sfv.sfv_list[count_entries]->state = s.st_size;
    count_entries++;
  } /* while ((entr=readdir(dir))!=NULL) */
  sfv.comments[count_comments] = NULL;
  sfv.sfv_list[count_entries] = NULL;

  /* writes file */
  {
    char buffer[2048];
    int fd_sfv;
    fd_sfv = open(sfv_file,O_CREAT | O_WRONLY | O_TRUNC,0644);

    i=0;
    while (sfv.comments[i]) {
      write(fd_sfv,sfv.comments[i],strlen(sfv.comments[i]));
      write(fd_sfv,"\n",1);
      i++;
    }
    i=0;
    while (sfv.sfv_list[i]) {
      if (snprintf(buffer,2047,"%s %lx\n",sfv.sfv_list[i]->filename,
	    sfv.sfv_list[i]->crc) <= 0) return -1;
      ret = strlen(buffer);
      if ( write(fd_sfv,buffer,ret) != ret ) {
	out_err(LEVEL_CRITICAL,"Unable to write sfv_file (%s)\n",strerror(errno));
       	return -1;
      }
      i++;
    }

    close(fd_sfv);
  }

  sfv_free(&sfv);
  return 0;
}

/* checks sfv file
 * returns 0 if all ok
 * number 0xaaabbb: a == missing files, b == errors
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_check(const char * sfv_file)
{
  int ret=0, thisret;
  char * ptr;
  char dir[1024];
  char filename[2048];
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(dir,sfv_file,1023);
  ptr = strrchr(dir,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  i=0;
  strcpy(filename,dir);
  ptr = filename + strlen(dir);
  while (sfv.sfv_list[i]) {
    strcpy(ptr,sfv.sfv_list[i]->filename);
    if (stat(filename,&s) || S_ISDIR(s.st_mode)) {
      ret += 0x1000;
      sfv.sfv_list[i]->state = SFV_MISSING;
    } else {
      thisret = calc_crc32(filename,&crc);
      if (thisret || crc != sfv.sfv_list[i]->crc) {
        ret ++;
	sfv.sfv_list[i]->state = SFV_BAD;
      }
      else {
	sfv.sfv_list[i]->state = SFV_OK;
      }
#ifdef DEBUG
out_err(LEVEL_CRITICAL,"file %s calculated: %08lX reference: %08lX\n",filename,crc,sfv.sfv_list[i]->crc);
#endif
    }
    *ptr = '\0';
    i++;
  }

  sfv_free(&sfv);
  return ret;
}

/* find sfv file in same dir than file
 * file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 if sfv found and file present in sfv, and put crc
 * 1 if no sfv found or sfv found but file not present
 */
int sfv_find_sfv(const char * file, wzd_sfv_file *sfv, wzd_sfv_entry ** entry)
{
  DIR *dir;
  char sfv_dir[1024];
  char stripped_filename[1024];
  char *ptr;
  struct dirent *entr;
  unsigned int length;
  int ret;

  if (strlen(file) > 1023) return -1;

  strcpy(sfv_dir,file);
  ptr = strrchr(sfv_dir,'/');
  if (!ptr) return -1;
  *ptr = '\0';
  strncpy(stripped_filename,ptr+1,1023);
  if (strlen(stripped_filename)<=0) return -1;

  if ( (dir=opendir(sfv_dir)) == NULL ) return -1;

  sfv_init(sfv);

  while ( (entr=readdir(dir)) != NULL ) {
    if (strcmp(entr->d_name,".")==0 ||
	strcmp(entr->d_name,"..")==0 ||
        strcmp(entr->d_name,HARD_PERMFILE)==0)
    continue;
    length = strlen(entr->d_name);
    if (length<5) continue;
    if (strcasecmp(entr->d_name+length-3,"sfv")==0)
    {
      char sfv_name[1024];
      int i;
      i = 0;
      ptr = sfv_dir;
      while (*ptr) {
	if (i >= 1022) continue;
	sfv_name[i] = *ptr;
	i++;
	ptr++;
      }	
      sfv_name[i++] = '/';
      ptr = entr->d_name;
      while (*ptr) {
	if (i >= 1023) continue;
	sfv_name[i] = *ptr;
	i++;
	ptr++;
      }	
      *ptr = '\0';
      sfv_name[i]='\0';
      ret = sfv_read(sfv_name,sfv);
#ifdef DEBUG
      out_err(LEVEL_CRITICAL,"sfv file: %s\n",entr->d_name);
#endif
      if (ret == -1 || sfv->sfv_list == NULL) { closedir(dir); return -1; }
      /* sfv file found, check if file is in sfv */
      i = 0;
      while (sfv->sfv_list[i]) {
#ifdef __CYGWIN__
	if (strcasecmp(stripped_filename,sfv->sfv_list[i]->filename)==0) {
#else /* __CYGWIN__ */
	if (strcmp(stripped_filename,sfv->sfv_list[i]->filename)==0) {
#endif /* __CYGWIN__ */
	  *entry = sfv->sfv_list[i];
	  closedir(dir);
	  return 0;
	}
	i++;
      }
      sfv_free(sfv);
    }
  } /* while readdir */

  closedir(dir);

  return 1;
}

/* called after a sfv file is uploaded
 * sfv_file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 else
 */
int sfv_process_new(const char *sfv_file, wzd_context_t *context)
{
  wzd_sfv_file sfv;
  char dir[1024];
  char filename[2048];
  char *ptr;
  int i;

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(dir,sfv_file,1023);
  ptr = strrchr(dir,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  i=0;
  strcpy(filename,dir);
  ptr = filename + strlen(dir);
  while (sfv.sfv_list[i]) {
    strcpy(ptr,sfv.sfv_list[i]->filename);
    /* Check file ? - means sfv uploaded AFTER files */
    sfv_check_create(filename,sfv.sfv_list[i]);

    *ptr = '\0';
    i++;
  }

  /* create a dir/symlink to mark incomplete */
  if (strlen(dir)>2)
  {
    const char * incomplete;
    char dirname[256];
    if (dir[strlen(dir)-1]=='/') dir[strlen(dir)-1]='\0';
    ptr = strrchr(dir,'/');
    if (ptr) {
      strncpy(dirname,ptr+1,255);
      incomplete = c_incomplete(incomplete_indicator,dirname);
      /* create empty file|dir / symlink ? */
      if (dir[strlen(dir)-1]!='/') strcat(dir,"/");
      strcat(dir,incomplete);
      if (!checkabspath(dir,filename,context))
      {
	/* symlink ? */
	if (symlink(dirname,filename) && errno != EEXIST)
	{
	  out_log(LEVEL_INFO,"Symlink creation failed (%s -> %s) %d (%s)\n",
	      dir, filename, errno, strerror(errno));
	}
	/* empty file ? */
/*	close(creat(filename,0400));*/
      }
    }
  }

  sfv_free(&sfv);
  return 0;
}

/* Converts cookies in incomplete indicators */
char i_buf[ 256 ];
char * c_incomplete(char *instr, char *path)
{
  char *buf_p;

  buf_p = i_buf;
  for ( ; *instr ; instr++ ) if ( *instr == '%' ) {
    instr++;
    switch ( *instr ) {
/*      case '0': buf_p += sprintf( buf_p, "%s", path[0] ); break;
      case '1': buf_p += sprintf( buf_p, "%s", path[1] ); break;*/
       case '0': buf_p += sprintf( buf_p, "%s", path ); break;
      case '%': *buf_p++ = '%' ; break;
    }
  } else {
    *buf_p++ = *instr;
  }
  *buf_p = 0;
  return i_buf;
}

char output[2048];
/* Converts cookies in complete indicators
 *
 * NOTE: sfv file MUST be filled !
 */
const char *_sfv_convert_cookies(char * instr, const char *dir, wzd_sfv_file sfv)
{
 int 	val1, val2;
/* int	n, from, to, reverse;*/
 char	*out_p;
 char	*m;
 char	ctrl[10];
 int	total_files = 0, i;
 double	total_size=0;
 struct stat s;
 char	buffer[1024];
 size_t	len;

 strncpy(buffer,dir,1023);
 len = strlen(dir);
 if (buffer[len-1] != '/') { buffer[len-1]='/'; len++; }
 i=0;
 while (sfv.sfv_list[i]) {
   strcpy(buffer+len,sfv.sfv_list[i]->filename);
   if (!stat(buffer,&s)) {
     total_size += (s.st_size / 1024.);
   }
   buffer[len]='\0';
   i++;
 }
 total_files = i;

 out_p = output;

 for ( ; *instr ; instr++ ) if ( *instr == '%' ) {
	instr++;
	m = instr;
	if (*instr == '-' && isdigit(*(instr + 1))) instr += 2;
	while (isdigit(*instr)) instr++;
	if ( m != instr ) {
		sprintf(ctrl, "%.*s", instr - m, m);
		val1 = atoi(ctrl);
		} else {
		val1 = 0;
		}

	if ( *instr == '.' ) {
		instr++;
		m = instr;
		if (*instr == '-' && isdigit(*(instr + 1))) instr += 2;
		while (isdigit(*instr)) instr++;
		if ( m != instr ) {
			sprintf(ctrl, "%.*s", instr - m, m);
			val2 = atoi(ctrl);
			} else {
			val2 = 0;
			}
		} else {
		val2 = -1;
		}

	 switch ( *instr ) {
#if 0
		case 'a': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / raceI->total.speed)); break;
		case 'A': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / ((raceI->transfer_stop.tv_sec - raceI->transfer_start.tv_sec) + (raceI->transfer_stop.tv_usec - raceI->transfer_start.tv_usec) / 1000000.) / 1024)); break;
		case 'b': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.size); break;
		case 'B': out_p += sprintf(out_p, "\\002"); break;
		case 'c':
			from = to = reverse = 0;
			instr++;
			m = instr;
			if ( *instr == '-' ) {  
				reverse = 1;
				instr++;
				}

			for ( ; isdigit(*instr) ; instr++ ) {
				from *= 10;
				from += *instr - 48;
				}

			if ( *instr == '-' ) {
				instr++;
				for ( ; isdigit(*instr) ; instr++ ) { 
					to *= 10;
					to += *instr - 48;
					}
				if ( to == 0 || to >= raceI->total.groups ) {
					to = raceI->total.groups - 1;
					}
				}

			if ( to < from ) {
				to = from;
				}

			if ( reverse == 1 ) {
				n = from;
				from = raceI->total.groups - 1 - to;
				to = raceI->total.groups - 1 - n;
				}

			if ( from >= raceI->total.groups ) {
				to = -1;
				}

			for ( n = from ; n <= to ; n++ ) {
				out_p += sprintf(out_p, "%*.*s", val1, val2, convert3(raceI, groupI[groupI[n]->pos], group_info, n));
				}
			instr--;
			break;
		case 'C':
			from = to = reverse = 0;
			instr++;
			m = instr;
			if ( *instr == '-' ) {  
				reverse = 1;
				instr++;
				}

			for ( ; isdigit(*instr) ; instr++ ) {
				from *= 10;
				from += *instr - 48;
				}

			if ( *instr == '-' ) {
				instr++;
				for ( ; isdigit(*instr) ; instr++ ) { 
					to *= 10;
					to += *instr - 48;
					}
				if ( to == 0 || to >= raceI->total.users ) {
					to = raceI->total.users - 1;
					}
				}

			if ( to < from ) {
				to = from;
				}

			if ( reverse == 1 ) {
				n = from;
				from = raceI->total.users - 1 - to;
				to = raceI->total.users - 1 - n;
				}

			if ( from >= raceI->total.users ) {
				to = -1;
				}

			for ( n = from ; n <= to ; n++ ) {
				out_p += sprintf(out_p, "%*.*s", val1, val2, convert2(raceI, userI[userI[n]->pos], groupI, user_info, n)); break;
				}
			instr--;
			break;
		case 'd': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)hms(raceI->transfer_stop.tv_sec - raceI->transfer_start.tv_sec)); break;
		case 'e': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->file.size * raceI->total.files >> 10) / 1024.)); break;
#endif
		case 'f': out_p += sprintf(out_p, "%*i", val1, (int)total_files); break;
#if 0
		case 'F': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.files - raceI->total.files_missing); break;
		case 'g': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.groups); break;
		case 'G': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->user.group); break;
		case 'k': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / 1024.)); break;
		case 'l': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)convert2(raceI, userI[raceI->misc.slowest_user[1]], groupI, slowestfile, 0)); break;
		case 'L': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)convert2(raceI, userI[raceI->misc.fastest_user[1]], groupI, fastestfile, 0)); break;
#endif
		case 'm': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(total_size / 1024.)); break;
#if 0
		case 'M': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.files_missing); break;
		case 'n': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->file.name); break;
		case 'o': out_p += sprintf(out_p, "%*i", val1, val2, (int)raceI->total.files_bad); break;
		case 'O': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->total.bad_size >> 10) / 1024.)); break;
		case 'p': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->total.files - raceI->total.files_missing) * 100. / raceI->total.files)); break;
		case 'P': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.bad_size / 1024.)); break;
		case 'S': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->file.speed / 1024.)); break;
		case 'r': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.release_name); break;
		case 'R': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.racer_list + 1); break;
		case 't': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.top_messages[1] + 1); break;
		case 'T': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.top_messages[0] + 1); break;
		case 'u': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.users); break;
		case 'U': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->user.name); break;
		case 'v': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.error_msg); break;
		case 'V': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.progress_bar); break;

		/* Audio */

		case 'w': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_genre); break;
		case 'W': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_album); break;
		case 'x': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_artist); break;
		case 'y': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_title); break;
		case 'Y': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_year); break;
		case 'X': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.bitrate); break;
		case 'z': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.samplingrate); break;
		case 'h': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.codec); break;
		case 'q': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.layer); break;
		case 'Q': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.channelmode); break;

		/* Video */

		case 'D': out_p += sprintf(out_p, "%*i", val1, raceI->video.width); break;
		case 'E': out_p += sprintf(out_p, "%*i", val1, raceI->video.height); break;
		case 'H': out_p += sprintf(out_p, "%*i", val1, raceI->video.fps); break;

		/* Other */

		case 'Z': *out_p++ = raceI->file.compression_method; break;
		case '%': *out_p++ = *instr;
#endif
		}
	} else *out_p++ = *instr;
 *out_p = 0;
 return output;
}

/* updates complete bar (erasing preceding one if existing) */
void sfv_update_completebar(wzd_sfv_file sfv, const char *filename, wzd_context_t * context)
{
  char dir[512];
  char *ptr;
  size_t len;
  regex_t preg;
  regmatch_t pmatch[1];

  /* do NOT comment this, we get len here ! */
  if (!filename || (len=strlen(filename))<2 || filename[0]!='/') return;
  ptr = strrchr(filename,'/');
  len = (ptr-filename)+1; /* +1 because we want the / */
  strncpy(dir,filename,len);
  dir[len]='\0';
  
  regcomp( &preg, del_progressmeter, REG_NEWLINE|REG_EXTENDED );
  {
    char buffer[512];
    DIR *d;
    struct dirent *entr;
    float percent;

    /* Removes previous progressmeter */
    if ( (d=opendir(dir))==NULL ) return;
    while ((entr=readdir(d))!=NULL) {
      if (entr->d_name[0]=='.') continue;
      if ( regexec( &preg, entr->d_name, 1, pmatch, 0) == 0 ) {
	/* found, remove it  */
	/* security check */
	if (len+strlen(entr->d_name)>510) continue;
	strcpy(dir+len,entr->d_name);
	remove (dir);
	dir[len]='\0';
      }
    }
    percent = _sfv_get_release_percent(dir, sfv);
    if (percent >= 100.f) { /* complete */
      const char *complete;
      const char *incomplete;
      char dirname[512];
      /* create complete tag */
      complete = _sfv_convert_cookies(other_completebar,dir,sfv);
      strcpy(dir+len,complete);
      mkdir(dir,0755);
      dir[len]='\0';
      /* remove incomplete symlink */
      if (dir[strlen(dir)-1]=='/') dir[strlen(dir)-1]='\0';
      ptr = strrchr(dir,'/');
      if (ptr) {
	strncpy(dirname,ptr+1,255);
	incomplete = c_incomplete(incomplete_indicator,dirname);
	/* remove empty file|dir / symlink */
	if (dir[strlen(dir)-1]!='/') strcat(dir,"/");
	strcat(dir,incomplete);
	if (!checkabspath(dir,buffer,context))
	{
	  remove(buffer);
	}
      }
    } else { /* incomplete */
      snprintf(buffer,255,progressmeter,(int)percent);

      strcat(dir,buffer);
      /* create empty dir ? */
      mkdir (dir,0755);
    } /* complete ? */
  }  
}

/* parse dir to calculate release completion % */
float _sfv_get_release_percent(const char *dir, wzd_sfv_file sfv)
{
  float percent=0.f;
  char buffer[512], missing[512], bad[512];
  size_t len, len_file;
  int i;
  unsigned int count=0, total_count=0;
  struct stat s;

  if (sfv.sfv_list == NULL) return 0;
  
  strncpy(buffer,dir,511);
  len = strlen(buffer);
  if (buffer[len-1] != '/') { buffer[len-1]='/'; len++; }
    /* note: we do not write '\0' because strncpy pads buffer with 0's */

  i=0;
  while (sfv.sfv_list[i])
  {
    total_count++;
    len_file = strlen(sfv.sfv_list[i]->filename);
    if (511-len <= len_file+8) continue;
      /* 8 is strlen("-missing") */
    strcpy(buffer+len,sfv.sfv_list[i]->filename);
    strcpy(missing,buffer);
    strcpy(missing+len+len_file,".missing");
    strcpy(bad,buffer);
    strcpy(bad+len+len_file,".bad");
    if ( stat(buffer,&s)==0 && stat(missing,&s) && stat(bad,&s) ) {
      count++;
    } else {
      if ( stat(buffer,&s) ) {
	if ( !stat(bad,&s) )
	  remove(bad);
	if ( stat(missing,&s) )
	  close(open(missing,O_WRONLY|O_CREAT,0666));
      }
    }
    i++;
  }
  if (count == total_count) return 100.f;

  percent = count * 100.f / total_count;
  return percent;
}

void do_site_help_sfv(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];

  snprintf(buffer,BUFFER_LEN,"Syntax error in command SFV\n");
  strcat(buffer," SITE SFV CHECK sfv_filename\n");
  strcat(buffer," SITE SFV CREATE sfv_filename\n");
  strcat(buffer," ");
  send_message_with_args(501,context,buffer);
}

/********************* do_site_sfv *************************/
/* sfv: add / check / create
 * check sfv_name
 * create new_sfv_name
 */
void do_site_sfv(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * command, *name;
  int ret;
  wzd_sfv_file sfv;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help_sfv(context);
    return;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);

  if (!name) {
    do_site_help_sfv(context);
    return;
  }

  /* convert file to absolute path, remember sfv wants ABSOLUTE paths ! */
  if ( (ret = checkpath(name,buffer,context)) != 0 ) {
    do_site_help_sfv(context);
    return;
  }
/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
  sfv_init(&sfv);

  if (strcasecmp(command,"add")==0) {
    ret = send_message_with_args(200,context,"Site SFV add successfull");
  }
  if (strcasecmp(command,"check")==0) {
    ret = sfv_check(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else if (ret < 0) {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
    else {
      char buf2[128];
      snprintf(buf2,128,"SFV check: missing files %d;  crc errors %d", (ret >> 12),ret & 0xfff);
      ret = send_message_with_args(501,context,buf2);
    }
  }
  if (strcasecmp(command,"create")==0) {
    ret = sfv_create(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
  }
  
  sfv_free(&sfv);
}


/***** EVENT HOOKS *****/
int sfv_hook_preupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  int ret;
  int length;

  /* check file type */
  length = strlen(filename);
  if (length >= 4) {
    if (strcasecmp(filename+length-4,".sfv")==0) /* do not check sfv files against themselves ... */
      return 0;
  }
  ret = sfv_find_sfv(filename,&sfv,&entry);
  switch (ret) {
  case 0:
#ifdef DEBUG
    out_err(LEVEL_CRITICAL,"sfv_hook_preupload user %s file %s, ret %d crc %08lX\n",username,filename,ret,entry->crc);
#endif
    break;
  case 1:
#ifdef DEBUG
    out_err(LEVEL_CRITICAL,"No sfv found or file not present in sfv\n");
#endif
    break;
  default:
    /* error */
    return -1;
  }
  sfv_free(&sfv);
  return 0;
}

int sfv_hook_postupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  unsigned long crc, real_crc;
  int ret;
  int length;
  wzd_context_t * context;

  context = GetMyContext();

  /* check file type */
  length = strlen(filename);
  if (length >= 4) {
    if (strcasecmp(filename+length-4,".sfv")==0) /* Process a new sfv file */
      return sfv_process_new(filename,context);
  }
  crc = 0;
  ret = sfv_find_sfv(filename,&sfv,&entry);
  switch (ret) {
  case 0:
#ifdef DEBUG
    out_err(LEVEL_CRITICAL,"sfv_hook_postupload user %s file %s, crc %08lX OK\n",username,filename,entry->crc);
#endif
    break;
  case 1:
#ifdef DEBUG
    out_err(LEVEL_CRITICAL,"No sfv found or file not present in sfv\n");
#endif
    return 1;
  default:
    /* error */
    return -1;
  }
  ret = calc_crc32(filename,&real_crc);
  if (ret) {
    sfv_free(&sfv);
    return -1;
  }
  sfv_check_create(filename,entry);

  sfv_update_completebar(sfv,filename,context);

  sfv_free(&sfv);
  return ret;
}

int sfv_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args)
{
  if (strcasecmp(token,"SFV")==0) {
    char buffer[BUFFER_LEN];
    strncpy(buffer,args,BUFFER_LEN-1);
    do_site_sfv(buffer,context);
    return 0;
  }

  return 1;
}

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
/*  printf("WZD_MODULE_INIT\n");*/
/*  out_err(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);*/
  hook_add(&getlib_mainConfig()->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
  hook_add(&getlib_mainConfig()->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
  hook_add(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&sfv_hook_site);
#ifdef DEBUG
  out_err(LEVEL_INFO,"module sfv: hooks registered\n");
#endif
  return 0;
}

