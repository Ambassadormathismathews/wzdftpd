/* vi:ai:et:ts=8 sw=2
 */
/*
 *
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 *
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* isspace */

#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifndef _MSC_VER
#include <unistd.h>
#ifndef BSD
#include <crypt.h>
#endif /* BSD */
#endif

#include "wzd_auth.h"

/* return 1 if password matches */

int checkpass_crypt(const char *pass, const char *encrypted)
{
  char * cipher;

  if (!pass || !encrypted) return 0;

  /* FIXME - crypt is NOT reentrant */
  cipher = crypt(pass,encrypted);
  return strcmp(cipher,encrypted)==0;
}

int changepass_crypt(const char *pass, char *buffer, size_t len)
{
  char * cipher;
  char salt[3];

  if (!pass || !buffer || len<=0) return -1;

  salt[0] = 'a' + (char)(rand()%26);
  salt[1] = 'a' + (char)((rand()*72+3)%26);

  /* FIXME - crypt is NOT reentrant */
  cipher = crypt(pass, salt);
  strncpy(buffer,cipher,len);

  return 0;
}

