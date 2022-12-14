/* Copyright (c) 2022 Georg Richter

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA */

#ifdef HAVE_NETTLE
#include <nettle/aes.h>
#include <nettle/gcm.h>
#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/nettle-meta.h>
#include <nettle/yarrow.h>
#include <nettle/macros.h>

typedef struct st_nettle_ctx {
  union {
    const struct nettle_aead *a;       /* used by GCM only */
    const struct nettle_cipher *c;
  } cipher;
  void *ctx;                           /* nettle cipher context */
  enum ma_aes_mode mode;               /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  unsigned char src_len;
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
} *_CW_CRYPT_CTX;
#elif HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct st_openssl_ctx {
  EVP_CIPHER_CTX *ctx;
  enum ma_aes_mode mode;               /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
} *_CW_CRYPT_CTX;
#elif HAVE_SCHANNEL

#include <windows.h>
#include <bcrypt.h>

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif
#define __attribute__(a)
typedef struct st_schannel_ctx {
  BCRYPT_ALG_HANDLE AlgHdl;
  BCRYPT_KEY_HANDLE KeyHdl;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
  PBYTE pIv;
  PBYTE pKey;
  DWORD blocklen;
  unsigned char authtag[AES_BLOCK_SIZE];
  enum ma_aes_mode mode;               /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
} *_CW_CRYPT_CTX;
#endif

