#include "wzd.h"

#include <regex.h>

#define BUFSIZE	1024

wzd_config_t tempConfig;



int set_default_options(void)
{
  mainConfig = &tempConfig;

  tempConfig.backend.handle=NULL;

  tempConfig.port = 21;
  tempConfig.max_threads=32;

  tempConfig.limiter_ul = NULL;
  tempConfig.limiter_dl = NULL;

  tempConfig.pasv_low_range = 1025;
  tempConfig.pasv_up_range = 65536;

  tempConfig.login_pre_ip_check = 0;
  tempConfig.login_pre_ip_allowed = NULL;
  tempConfig.login_pre_ip_denied = NULL;

  tempConfig.vfs = NULL;

  tempConfig.logfilename = malloc(256);
  strcpy(tempConfig.logfilename,"wzd.log");

  tempConfig.logfilemode = malloc(3);
  strcpy(tempConfig.logfilemode,"a");

  tempConfig.logfile = NULL;

  tempConfig.loglevel=LEVEL_LOWEST;

  tempConfig.perm_list = NULL;

  /* site config */
  tempConfig.site_config.file_help[0] = '\0';
  tempConfig.site_config.file_rules[0] = '\0';
  tempConfig.site_config.file_who[0] = '\0';

#if SSL_SUPPORT
  memset(tempConfig.tls_certificate,0,sizeof(tempConfig.tls_certificate));
  strcpy(tempConfig.tls_cipher_list,"ALL");

  tempConfig.tls_type = TLS_NOTYPE;
#endif

  tempConfig.shm_key = 0x1331c0d3;

  memset(tempConfig.pasv_ip,0,4);

  return 0;
}

int parseVariable(const char *varname, const char *value);


int do_permission_line(const char *permname, const char *permline)
{
  int ret;

  ret = perm_is_valid_perm(permname);
  if (ret) return 1;

  ret = perm_add_perm(permname, permline,mainConfig);
  if (ret) return 1;

  return 0;
}


int readConfigFile(const char *fileName)
{
  int err;
  FILE * configfile;
  char buffer[BUFSIZE];
  char varname[BUFSIZE];
  char value[BUFSIZE];
  char * ptr;
  int length;
  regex_t reg_line;
  regmatch_t regmatch[3];

  init_default_messages();
  set_default_options();

  configfile = fopen(fileName,"r");
  if (!configfile)
    return 0;

  while (fgets(buffer,BUFSIZE,configfile))
  {
    ptr = buffer;
    length = strlen(buffer); /* fgets put a '\0' at the end */
    /* trim leading spaces */
    while (((*ptr)==' ' || (*ptr)=='\t') && (length-- > 0))
      ptr++;
    if ((*ptr)=='#' || length<=1)	/* comment and empty lines */
      continue;

    /* TODO if line contains a " and is not ended, it is a multi-line */
    /* TODO replace special chars (\n,\t,\xxx,etc) */

    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    if (length <= 0) continue;

    reg_line.re_nsub = 2;
    err = regcomp (&reg_line, "^([-]?[a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
    if (err) {
      out_log(LEVEL_CRITICAL,"Regexp could not compile (file %s line %d)\n",__FILE__,__LINE__);
      out_log(LEVEL_CRITICAL,"Possible error cause: bad libc installation\n");
      exit (1);
    }

    err = regexec(&reg_line,ptr,3,regmatch,0);
    if (err) {
      out_log(LEVEL_HIGH,"Line '%s' does not respect config line format - ignoring\n",buffer);
    } else {
      memcpy(varname,ptr+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
      varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
      memcpy(value,ptr+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
      value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

      err = parseVariable(varname,value);
      if (err) {
        out_log(LEVEL_HIGH,"Line '%s' is not a valid config line (probably var name mistake) - ignoring\n",buffer);
      }
    }
  }
	


  fclose(configfile);

//  mainConfig = malloc(sizeof(wzd_config_t));
  mainConfig_shm = wzd_shm_create(tempConfig.shm_key-1,sizeof(wzd_config_t),0);
  if (mainConfig_shm == NULL) {
    /* 2nd chance */
    wzd_shm_cleanup(tempConfig.shm_key-1);
    mainConfig_shm = wzd_shm_create(tempConfig.shm_key-1,sizeof(wzd_config_t),0);
    if (mainConfig_shm == NULL) {
      fprintf(stderr,"MainConfig shared memory zone could not be created !\n");
      exit(1);
    }
  }
  mainConfig = mainConfig_shm->datazone;
  memcpy(mainConfig,&tempConfig,sizeof(wzd_config_t));

  return 0;
}

int parseVariable(const char *varname, const char *value)
{
  long i;
  unsigned long l;

  /* PORT (int)
   * 2 remarks:
   * - use strtoul (instead of atoi) to detect errors
   * - base can be 10 (default), 16 ( 0xnum ) or 8 ( 0num )
   */
  if (strcasecmp("port",varname)==0)
  {
    errno = 0;
    i = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (i < 1 || i > 65535) {
      out_log(LEVEL_HIGH,"port must be between 1 and 65535 inclusive\n");
      return 1;
    }
    out_log(LEVEL_INFO,"******* changing port: new value %d\n",i);
    tempConfig.port = i;
    return 0;
  }
  /* MAX_THREADS (int)
   * must be between 1 and 2000
   */
  if (strcasecmp("max_threads",varname)==0)
  {
    errno = 0;
    i = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (i < 1 || i > 2000) {
      out_log(LEVEL_HIGH,"max_threads must be between 1 and 2000 inclusive\n");
      return 1;
    }
    out_log(LEVEL_INFO,"******* changing max_threads: new value %d\n",i);
    tempConfig.max_threads = i;
    return 0;
  }
  /* BACKEND (string)
   * name of a .so
   */
  if (strcasecmp("backend",varname)==0)
  {
    out_log(LEVEL_INFO,"trying backend; '%s'\n",value);
    i = backend_validate(value);
    if (!i) {
      if (tempConfig.backend.handle == NULL) {
        i = backend_init(value);
      } else { /* multiple backends ?? */
	i=0;
      }
    }
    return i;
  }
  /* MAX_UL_SPEED (unsigned long)
   */
  if (strcasecmp("max_ul_speed",varname)==0)
  {
    errno = 0;
    l = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (tempConfig.limiter_ul) {
      out_log(LEVEL_HIGH,"Have you define max_ul_speed multiple times ? This one (%lu) will be ignored !\n",l);
      return 1;
    }
    out_log(LEVEL_INFO,"******* setting max_ul_speed : %lu\n",l);
    tempConfig.limiter_ul = limiter_new(l);
    return 0;
  }
  /* MAX_DL_SPEED (unsigned long)
   */
  if (strcasecmp("max_dl_speed",varname)==0)
  {
    errno = 0;
    l = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    if (tempConfig.limiter_dl) {
      out_log(LEVEL_HIGH,"Have you define max_dl_speed multiple times ? This one (%lu) will be ignored !\n",l);
      return 1;
    }
    out_log(LEVEL_INFO,"******* setting max_dl_speed : %lu\n",l);
    tempConfig.limiter_dl = limiter_new(l);
    return 0;
  }
  /* PASV_LOW_RANGE (unsigned long)
   */
  if (strcasecmp("pasv_low_range",varname)==0)
  {
    errno = 0;
    l = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    out_log(LEVEL_INFO,"******* setting pasv_low_range : %lu\n",l);
    tempConfig.pasv_low_range = l;
    return 0;
  }
  /* PASV_UP_RANGE (unsigned long)
   */
  if (strcasecmp("pasv_up_range",varname)==0)
  {
    errno = 0;
    l = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    out_log(LEVEL_INFO,"******* setting pasv_up_range : %lu\n",l);
    tempConfig.pasv_up_range = l;
    return 0;
  }
  /* PASV_IP (ip)
   */
  if (strcasecmp("pasv_ip",varname)==0)
  {
    unsigned int new_ip[4];
    int r;
    r = sscanf(value,"%u.%u.%u.%u",&new_ip[0],&new_ip[1],&new_ip[2],&new_ip[3]);
    if (r!=4 || new_ip[0] >= 255 || new_ip[1] >= 255 || new_ip[2] >= 255 || new_ip[3] >= 255)
      return 1;
    tempConfig.pasv_ip[0] = (unsigned char)new_ip[0];
    tempConfig.pasv_ip[1] = (unsigned char)new_ip[1];
    tempConfig.pasv_ip[2] = (unsigned char)new_ip[2];
    tempConfig.pasv_ip[3] = (unsigned char)new_ip[3];
    return 0;
  }
  /* LOGIN_PRE_IP_CHECK (int)
   */
  if (strcasecmp("login_pre_ip_check",varname)==0)
  {
    if ((*value != '0' && *value != '1' && *value != '2')
           || *(value+1)!='\0')
      return 1;
    tempConfig.login_pre_ip_check = (*value) - '0';
    return 0;
  }
  /* LOGIN_PRE_IP_ALLOWED (string)
   */
  if (strcasecmp("login_pre_ip_allowed",varname)==0)
  {
    if (ip_add(&tempConfig.login_pre_ip_allowed,value)) return 1;
    return 0;
  }
  /* LOGIN_PRE_IP_DENIED (string)
   */
  if (strcasecmp("login_pre_ip_denied",varname)==0)
  {
    if (ip_add(&tempConfig.login_pre_ip_denied,value)) return 1;
    return 0;
  }
  /* SHM_KEY (unsigned long)
   */
  if (strcasecmp("shm_key",varname)==0)
  {
    errno = 0;
    l = strtoul(value,(char**)NULL, 0);
    if (errno==ERANGE)
      return 1;
    out_log(LEVEL_INFO,"******* changing shm_key: new value 0x%lx\n",l);
    tempConfig.shm_key = l;
    return 0;
  }
  /* SITE CONFIG
   */
  if (strcasecmp("sitefile_help",varname)==0)
  { strncpy(tempConfig.site_config.file_help,value,256); return 0; }
  if (strcasecmp("sitefile_rules",varname)==0)
  { strncpy(tempConfig.site_config.file_rules,value,256); return 0; }
  if (strcasecmp("sitefile_user",varname)==0)
  { strncpy(tempConfig.site_config.file_user,value,256); return 0; }
  if (strcasecmp("sitefile_who",varname)==0)
  { strncpy(tempConfig.site_config.file_who,value,256); return 0; }
#if SSL_SUPPORT
  /* CERTIFICATES
   * absolute file name
   */
  if (strcasecmp("tls_certificate",varname)==0)
  {
    out_log(LEVEL_INFO,"TLS Certificate name: %s\n",value);
    strcpy(tempConfig.tls_certificate,value);
    return 0;
  }
  /* CIPHER LIST
   * man ssl(3) for list & explanations
   */
  if (strcasecmp("tls_cipher_list",varname)==0)
  {
    out_log(LEVEL_INFO,"TLS Cipher list: %s\n",value);
    strcpy(tempConfig.tls_cipher_list,value);
    return 0;
  }
  /* MODE
   * implicit / explicit
   */
  if (strcasecmp("tls_mode",varname)==0)
  {
    out_log(LEVEL_INFO,"TLS mode: %s\n",value);
    if (strcasecmp("explicit",value)==0)
      tempConfig.tls_type = TLS_EXPLICIT;
    else if (strcasecmp("explicit_strict",value)==0)
      tempConfig.tls_type = TLS_STRICT_EXPLICIT;
    else if (strcasecmp("implicit",value)==0)
      tempConfig.tls_type = TLS_IMPLICIT;
    else
      return 1;
    return 0;
  }
#endif
  /* VFS : Virtual FileSystem
   */
  if (strcasecmp("vfs",varname)==0)
  {
    char virtual_path[1024];
    char physical_path[1024];
    char delimiter;
    const char *ptr = value;
    char *dstptr;
    unsigned int dstlen;

    if (strlen(value) < 5) return 1; /* basic precaution */
    delimiter = *ptr++;

    dstptr = virtual_path;
    dstlen = 0;
    while (*ptr) {
      if (*ptr == delimiter) break; /* end */
      if (dstlen++ == 1023) break; /* too long */
      *dstptr++ = *ptr++;
    }
    if (!*ptr || *ptr != delimiter) return 1;
    *dstptr = '\0';

    dstptr = physical_path;
    dstlen = 0;
    ptr++;
    while (*ptr) {
      if (*ptr == delimiter) break; /* end */
      if (dstlen++ == 1023) break; /* too long */
      *dstptr++ = *ptr++;
    }
    if (!*ptr || *ptr != delimiter) return 1;
    *dstptr = '\0';

    vfs_add(&mainConfig->vfs,virtual_path,physical_path);

    return 0;
  } /* vfs */
  /* INTERNAL SFV CHECKER
   */
  if (strcasecmp("internal_sfv_checker",varname)==0)
  {
    if (strcasecmp("1",value)==0) {
      hook_add(&mainConfig->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
      hook_add(&mainConfig->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
    }
    return 0;
  }

  /* PERMISSIONS
   */
  if (varname[0] == '-')
  {
    varname++;
    return do_permission_line(varname,value);
  }
  return 1;
}
