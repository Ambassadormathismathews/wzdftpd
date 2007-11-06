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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "wzd_auth.h"
#include "wzd_base64.h"
#include "wzd_krb5.h"

#include <libwzd-core/wzd_structs.h> /* struct wzd_context_t */
#include <libwzd-core/wzd_log.h> /* out_log */
#include <libwzd-core/wzd_misc.h> /* GetMyContext */
#include <libwzd-core/wzd_debug.h> /* assertions */

#if defined(HAVE_KRB5)

#include <krb5.h>
#include <gssapi/gssapi.h>

static void gss_log_errors (unsigned int level, int maj_stat, int min_stat);

struct _auth_gssapi_data_t {
  gss_name_t       server;
  gss_ctx_id_t     context_hdl;
  gss_cred_id_t    creds;
  gss_channel_bindings_t input_chan_bindings;
};

int auth_gssapi_init(auth_gssapi_data_t * data)
{
  gss_buffer_desc  name_token;
  OM_uint32 maj_stat, min_stat;
  wzd_context_t * context;
  char hostname[256];
  char *gss_services[] = { "ftp", 0, "host", 0 };
  char ** service;
  struct sockaddr_in remote, local;
  socklen_t addrlen;
#if 0
  u_char init_buf[4];
  u_char acct_buf[4];
#endif

  context = GetMyContext();
  if (!context) return 0;

  if(gethostname (hostname, sizeof(hostname)) < 0) {
    out_log(LEVEL_HIGH,"auth_gssapi_init: could not get our own hostname\n");
    return -1;
  }

  addrlen = sizeof(local);
  if (getsockname (context->controlfd, (struct sockaddr *)&local, &addrlen) < 0)
/*      || addrlen != sizeof(local))*/
  {
    out_log(LEVEL_HIGH,"auth_gssapi_init: could use getsockname()\n");
    return -1;
  }

  addrlen = sizeof(remote);
  if (getpeername (context->controlfd, (struct sockaddr *)&remote, &addrlen) < 0)
/*      || addrlen != sizeof(remote))*/
  {
    out_log(LEVEL_HIGH,"auth_gssapi_init: could use getpeername()\n");
    return -1;
  }

  *data = malloc(sizeof(struct _auth_gssapi_data_t));
  memset(*data,0,sizeof(struct _auth_gssapi_data_t));
  (*data)->context_hdl = GSS_C_NO_CONTEXT;

  for (service=gss_services; *service; service++) {
    char buffer[1024];

    snprintf(buffer, sizeof(buffer), "%s@%s", *service, hostname);
    name_token.value = buffer;
    name_token.length = strlen(buffer)+1;

    maj_stat = gss_import_name (&min_stat,
                                &name_token,
                                GSS_C_NT_HOSTBASED_SERVICE,
                                &(*data)->server);
    if (GSS_ERROR(maj_stat)) {
      out_log(LEVEL_HIGH,"auth_gssapi_init: error importing name '%s@%s':\n",*service,hostname);
      gss_log_errors (LEVEL_HIGH,maj_stat,min_stat);
      return -1;
    }
#ifdef WZD_DBG_KRB5
    out_log(LEVEL_INFO, "gss_import_name(%s) ok\n",buffer);
#endif
  }

#ifdef WZD_DBG_KRB5
  out_log(LEVEL_FLOOD,"auth_gssapi_init: acquiring credentials (uid = %d, keytab = %s)\n",
      (int)geteuid(), getenv( "KRB5_KTNAME") );
#endif

  maj_stat = gss_acquire_cred (&min_stat,
                               (*data)->server,
                               0,
                               GSS_C_NULL_OID_SET,
                               GSS_C_ACCEPT,
                               &(*data)->creds,
                               NULL,
                               NULL);
  if (maj_stat != GSS_S_COMPLETE) {
    out_log(LEVEL_HIGH,"auth_gssapi_init: getting credentials:\n");
    gss_log_errors (LEVEL_HIGH,maj_stat,min_stat);
    out_log(LEVEL_HIGH,"check your KRB5_KTNAME environment variable\n");
    return -1;
  }

  switch (remote.sin_family) {
#ifdef IPV6_SUPPORT
    case AF_INET6:
      out_log(LEVEL_FLOOD,"family: INET6\n");
      out_log(LEVEL_HIGH,"GSSAPI on IPv6 is NOT supported yet, aborting\n");
      return -1;
#endif
    case AF_INET:
      out_log(LEVEL_FLOOD,"family: INET\n");
      break;
    default:
      out_log(LEVEL_FLOOD,"family: unknown (%d)\n",remote.sin_family);
      break;
  };

#if 0
  (*data)->input_chan_bindings = calloc(sizeof(gss_channel_bindings_t),1);
  
  (*data)->input_chan_bindings->initiator_addrtype = GSS_C_AF_INET;
  (*data)->input_chan_bindings->initiator_address.length = 4;
  init_buf[0] = (remote.sin_addr.s_addr >> 24) & 0xFF;
  init_buf[1] = (remote.sin_addr.s_addr >> 16) & 0xFF;
  init_buf[2] = (remote.sin_addr.s_addr >>  8) & 0xFF;
  init_buf[3] = (remote.sin_addr.s_addr >>  0) & 0xFF;

  (*data)->input_chan_bindings->initiator_address.value = init_buf;
  (*data)->input_chan_bindings->acceptor_addrtype = GSS_C_AF_INET;

  (*data)->input_chan_bindings->acceptor_address.length = 4;
  acct_buf[0] = (local.sin_addr.s_addr >> 24) & 0xFF;
  acct_buf[1] = (local.sin_addr.s_addr >> 16) & 0xFF;
  acct_buf[2] = (local.sin_addr.s_addr >>  8) & 0xFF;
  acct_buf[3] = (local.sin_addr.s_addr >>  0) & 0xFF;
  (*data)->input_chan_bindings->acceptor_address.value = acct_buf;
  (*data)->input_chan_bindings->application_data.value = malloc(4);

  (*data)->input_chan_bindings->application_data.length = 0;
  (*data)->input_chan_bindings->application_data.value = NULL;
#else
  (*data)->input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
#endif

  return 0;
}

int auth_gssapi_accept_sec_context(auth_gssapi_data_t data, char * ptr_in,size_t length_in, char ** ptr_out, size_t * length_out)
{
  OM_uint32 maj_stat, min_stat, min_stat2;
  gss_buffer_desc input_token, output_token;
  gss_name_t client_name;
  gss_OID mechid;
  unsigned int ret_flags = 0;
  int error;

  input_token.value = calloc(strlen(ptr_in),1);
  if ((error = radix_encode((unsigned char*)ptr_in, input_token.value , (int *)&input_token.length, 1)) !=0  ) {
    out_log(LEVEL_HIGH,"GSSAPI: could no decode ADAT\n");
    return -1;
  }
  output_token.value = NULL;
  output_token.length = 0;

  *ptr_out = NULL;

#ifdef WZD_DBG_KRB5
  out_log(LEVEL_FLOOD,"DEBUG: input token is %ld bytes long\n",(long)input_token.length);
#endif

  maj_stat = gss_accept_sec_context (&min_stat,
                                     &data->context_hdl,
                                     data->creds, /* GSS_C_NO_CREDENTIAL, */
                                     &input_token,
                                     data->input_chan_bindings,
                                     &client_name,
                                     &mechid,
                                     &output_token,
                                     &ret_flags,
                                     NULL, /* ignore time_rec */
                                     /*&delegated_cred_handle*/ NULL);

  gss_release_buffer(&min_stat2,&input_token);

  if (output_token.length != 0) {
    *ptr_out = calloc(output_token.length*4 + 1,1);
    if ( (error = radix_encode(output_token.value, (unsigned char*)*ptr_out, (int *)&output_token.length, 0)) != 0 ) {
      out_log(LEVEL_HIGH,"GSSAPI: could no encode ADAT reply\n");
      return -1;
    }
    *length_out = strlen(*ptr_out);
  }

  if (maj_stat == GSS_S_COMPLETE) {
    out_log(LEVEL_FLOOD,"DEBUG: gssapi authentication succeeded\n");
    return 0; /* finished */
  }

  if (maj_stat == GSS_S_CONTINUE_NEEDED) {
    out_log(LEVEL_FLOOD,"DEBUG: we have to continue gssapi negotiation\n");
    return 1; /* we need more */
  }

  if (maj_stat != GSS_S_CONTINUE_NEEDED) {
    out_log(LEVEL_HIGH,"gss_accept_sec_context: Houston, we have a problem in gss_accept_sec_context\n");
  }

  if(GSS_ERROR(maj_stat)) {
    out_log(LEVEL_HIGH,"gss_accept_sec_context error (%lx,%lx):\n",(unsigned long)maj_stat,(unsigned long)min_stat);
    gss_log_errors (LEVEL_HIGH,maj_stat,min_stat);
    return -1;
  }
  if (output_token.length != 0) {
    *ptr_out = strdup(output_token.value);
    *length_out = output_token.length;

    return 1; /* we need more */
  }
  return -1;
}

int auth_gssapi_decode_mic(auth_gssapi_data_t data, char * ptr_in,size_t length_in, char ** ptr_out, size_t * length_out)
{
  int error;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc tokbuf, outbuf;
  int cflags;
  gss_qop_t quality;

  tokbuf.value = calloc(strlen(ptr_in),1);
  if ((error = radix_encode((unsigned char*)ptr_in, tokbuf.value , (int *)&tokbuf.length, 1)) !=0  ) {
    out_log(LEVEL_HIGH,"GSSAPI: could no decode MIC\n");
    return -1;
  }
  outbuf.value = NULL;
  outbuf.length = 0;

  *ptr_out = NULL;

  maj_stat = gss_unwrap (&min_stat,
                         data->context_hdl,
                         &tokbuf,
                         &outbuf,
                         &cflags,
                         &quality);
  if (maj_stat != GSS_S_COMPLETE) {
    out_log(LEVEL_HIGH,"gss_unwrap error (%lx,%lx):\n",(unsigned long)maj_stat,(unsigned long)min_stat);
    gss_log_errors (LEVEL_HIGH,maj_stat,min_stat);
    return -1;
  }

  if (outbuf.length != 0) {
    *ptr_out = strdup(outbuf.value);
    *length_out = outbuf.length;

    return 0;
  }

  return -1;
}

int auth_gssapi_encode(auth_gssapi_data_t data, char * ptr_in,size_t length_in, char ** ptr_out, size_t * length_out)
{
  int error;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc in_buf, out_buf;
  int conf_req_flag;
  int state;

  /* wrap message */
  in_buf.value = ptr_in;
  in_buf.length = length_in; /* XXX should be strlen(real_msg) + 1 at least */

  /* crypt message */
  state = 1;

  /* request confidentiality */
  conf_req_flag = 0;

  maj_stat = gss_wrap (&min_stat,
                       data->context_hdl,
                       conf_req_flag,
                       GSS_C_QOP_DEFAULT,
                       &in_buf,
                       &state,
                       &out_buf);
  if (maj_stat != GSS_S_COMPLETE) {
    out_log(LEVEL_HIGH,"gss_wrap error (%lx,%lx):\n",(unsigned long)maj_stat,(unsigned long)min_stat);
    gss_log_errors (LEVEL_HIGH,maj_stat,min_stat);
    return -1;
  }

  if (out_buf.length != 0) {
    *ptr_out = calloc(out_buf.length*4 + 4 + 1 + 2,1); /* 4 more characters for reply code + space, and 2 more for CRLF */
    memcpy(*ptr_out, "632 ", 4);
    if ( (error = radix_encode(out_buf.value, (unsigned char*)*ptr_out+4, (int *)&out_buf.length, 0)) != 0 ) {
      out_log(LEVEL_HIGH,"GSSAPI: could no encode reply\n");
      return -1;
    }
    *length_out = strlen(*ptr_out);
    memcpy(*ptr_out + *length_out, "\r\n", 2);
    (*length_out) += 2;
  }

#ifdef WZD_DBG_KRB5
    out_log(LEVEL_FLOOD,"DEBUG: encoded [%s]\n",*ptr_out);
#endif

  maj_stat = gss_release_buffer (&min_stat, &out_buf);

  return 0;
}

int auth_gssapi_read(fd_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  int ret;
  wzd_context_t * context = vcontext;

  WZD_ASSERT( msg != NULL );

  ret = clear_read(sock, msg, length, flags, timeout, vcontext);
  if (ret < 0) return ret;

  msg[ret] = '\0';

#ifdef WZD_DBG_KRB5
  out_log(LEVEL_FLOOD,"DEBUG: auth_gssapi_read %d = [%s]\n",ret,msg);
#endif

  if (ret > 3 && (strncasecmp(msg,"MIC ",4)==0 || strncasecmp(msg,"ENC ",4)==0)) { /** \todo XXX if text is ENC, decode message as such */
    char * ptr_out = NULL;
    size_t length_out;
    int err;

    chop(msg);

    err = auth_gssapi_decode_mic(context->gssapi_data, msg+4, strlen(msg+4), &ptr_out, &length_out);

#ifdef WZD_DBG_KRB5
    out_log(LEVEL_FLOOD,"DEBUG: decoded [%s]\n",ptr_out);
#endif

    if (length_out >= length) {
      out_log(LEVEL_CRITICAL,"FATAL: decoded MIC command is larger than base64\n");
      free(ptr_out);
      return -1;
    }

    strncpy(msg, ptr_out, length);
    ret = length_out;
  }

  return ret;
}

int auth_gssapi_write(fd_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  wzd_context_t * context = vcontext;
  int ret;
  char *ptr_out;
  size_t length_out;
  char * real_msg;

  WZD_ASSERT( msg != NULL );
  real_msg = wzd_strdup(msg);

  /* line breaks should not be included */
  while ( length > 0 && ( real_msg[length-1]=='\r' || real_msg[length-1]=='\n' ) ) {
    real_msg[length-1] = '\0';
    length--;
  }

#ifdef WZD_DBG_KRB5
  out_log(LEVEL_FLOOD,"DEBUG: auth_gssapi_write %d = [%s]\n",ret,real_msg);
#endif

  ret = auth_gssapi_encode(context->gssapi_data, real_msg, length, &ptr_out, &length_out);

  ret = clear_write(sock, ptr_out, length_out, flags, timeout, vcontext);

  free(ptr_out);

  return ret;
}

int check_krb5(const char *user, const char *data)
{
  return -1;
}

int changepass_krb5(const char *pass, char *buffer, size_t len)
{
  return -1;
}

static void gss_log_errors (unsigned int level, int maj_stat, int min_stat)
{
  OM_uint32 gmaj_stat, gmin_stat;
  OM_uint32 msg_ctx;
  gss_buffer_desc msg;

  msg_ctx = 0;
  while (!msg_ctx) {
    /* convert major status code (GSS-API error) to text */
    gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NULL_OID,
                                   &msg_ctx, &msg);
    if (gmaj_stat == GSS_S_COMPLETE) {
      out_log(level,"GSSAPI Error major: %s\n", (char*)msg.value);
      gss_release_buffer(&gmin_stat, &msg);
      break;
    }
    gss_release_buffer(&gmin_stat, &msg);
  }

  msg_ctx = 0;
  while (!msg_ctx) {
    /* convert minor status code (underlying routine error) to text */
    gmaj_stat = gss_display_status(&gmin_stat, min_stat,
                                   GSS_C_MECH_CODE,
                                   GSS_C_NULL_OID,
                                   &msg_ctx, &msg);
    if (gmaj_stat == GSS_S_COMPLETE) {
      out_log(level,"GSSAPI Error minor: %s\n", (char*)msg.value);
      gss_release_buffer(&gmin_stat, &msg);
      break;
    }
    gss_release_buffer(&gmin_stat, &msg);
  }
/*  out_log(level,"GSSAPI Error: %s\n", s);*/

}

#else /* ! HAVE_KRB5 */

int check_krb5(const char *user, const char *data)
{
  return -1;
}

int changepass_krb5(const char *pass, char *buffer, size_t len)
{
  return -1;
}

#endif /* HAVE_KRB5 */
