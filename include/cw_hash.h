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

#ifndef _cw_hash_h
#define _cw_hash_h

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

/** @file

   @brief
   Include file for for crypto hash functions.
*/

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
typedef EVP_MD_CTX *_CW_HASH_CTX;
typedef const EVP_MD *CW_HASH_TYPE;
#elif HAVE_NETTLE
#include <nettle/nettle-meta.h>
typedef const struct nettle_hash *CW_HASH_TYPE;
typedef struct st_nettle_hash_ctx {
  void *ctx;
  CW_HASH_TYPE hash;
} *_CW_HASH_CTX;
#elif HAVE_SCHANNEL
#include <windows.h>
#include <wincrypt.h>
struct st_hash_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct st_hash_ctx *_CW_HASH_CTX;
typedef int CW_HASH_TYPE;
#endif

/**
  Context for hash operations
*/
typedef void *CW_HASH_CTX;

/*! hash type enumeration */
enum cw_hash_alg {
#ifndef SECURE_HASHES
  CW_HASH_MD5,     /*!< MD5 hash (128-bit, 16 bytes)  */
  CW_HASH_SHA1,    /*!< SHA1 hash (160-bit, 20 bytes) */
#endif
  CW_HASH_SHA224,  /*!< SHA224 hash (224-bit, 28 bytes) */
  CW_HASH_SHA256,  /*!< SHA256 hash (256-bit, 32 bytes) */
  CW_HASH_SHA384,  /*!< SHA384 hash (384-bit, 48 bytes) */
  CW_HASH_SHA512,  /*!< SHA512 hash (512-bit, 64 bytes) */
};

/* function prototypes */

/**
  @brief wrapper function to acquire a context for hash
  calculations

  @param hash_alg [in]   hash algorithm

  @return                 hash context                         
 */
CW_HASH_CTX cw_hash_new(enum cw_hash_alg hash_alg);

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param ctx [in]       hash context
  @param buffer [in]    data buffer
  @param len [in]       size of buffer

  @return               void
*/

void cw_hash_input(CW_HASH_CTX ctx,
                   const unsigned char *buffer,
                   size_t len);

/**
  @brief retrieves the hash value from hash context 

  @param ctx [in]       hash context
  @param digest [in]    digest containing hash value

  @return               void
 */
void cw_hash_result(CW_HASH_CTX ctx, unsigned char *digest);

/**
  @brief deallocates hash context which was previoulsy allocated by
  cw_hash_new

  @param ctx [in]       hash context

  @return               void
 */
void cw_hash_free(CW_HASH_CTX ctx);
/**
  @brief wrapper function to compute hash from one or more
  buffers.

  @param hash_alg [in]   hashing hash_alg
  @param digest [out]     computed hash digest
  @param ... [in]         variable argument list containg touples of
  message and message lengths. Last parameter
  must be always NULL.

  @return                 void                         
 */

void cw_hashv(enum cw_hash_alg hash_alg,
              unsigned char *digest, ...);
/**
  @brief wrapper function to compute hash from message buffer

  @param hash_alg [in]   hash algorithm
  @param digest [out]    computed hash digest
  @param buffer [in]     message buffer
  @param length [in]     length of message buffer

  @return                void                         
*/
void cw_hash(enum cw_hash_alg hash_alg,
             unsigned char *digest,
             const unsigned char *buffer,
             size_t length);
/**
  @brief return digest size for given hash algorithm

  @param hash_alg [in]   hash algorithm

  @return                length of digest                         
 */
size_t cw_hash_digest_size(enum cw_hash_alg hash_alg);

#ifdef __cplusplus
}
#endif
#endif /* _cw_hash_h */
