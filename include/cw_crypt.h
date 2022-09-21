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

#ifndef _cw_crypt_h
#define _cw_crypt_h

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file

   @brief
   Include file for for cryptofunctions.
*/

/*! block cipher modes: Supported key sizes are 128, 192 and 256 bits */
enum ma_aes_mode {
  CW_AES_ECB, /*!< Electronic codebook mode */
  CW_AES_CBC, /*!< Cipher block chaining mode */
  CW_AES_GCM, /*!< Galois/counter mode */
  CW_AES_CTR  /*!< Counter mode */
};

/** \def encryption/decryption flags. */
#define CW_CRYPT_ENCRYPT  1 /*!< encrypt */
#define CW_CRYPT_DECRYPT  2 /*!< decrypt */
#define CW_CRYPT_NOPAD    4 /*!< don't pad automatically during encryption */

/** \def crypto errors */
#define CW_CRYPT_OK        0
#define CW_CRYPT_EINVKEY   1
#define CW_CRYPT_EINVCTX   2
#define CW_CRYPT_ENOMEM    3
#define CW_CRYPT_EINVIV    4
#define CW_CRYPT_EINVCIPH  5
#define CW_CRYPT_BADDATA   6
#define CW_CRYPT_ERND      7

#include <cw_crypt_internal.h>

/* \typedef crypto context */
typedef void *CW_CRYPT_CTX;

/* function prototypes */

/**
  @brief acquire a context for encryption
  and decryption. To prevent memory leaks the context must be
  released via cw_crypt_free

  @return                 crypt context or NULL on error
*/
CW_CRYPT_CTX cw_crypt_new();

/**
  @brief Frees a crypt context.
  
  @param crypt_ctx[in]  A crypto context which was previously allocated by
                        cw_crypt_new.
  
  @return               void
*/
void cw_crypt_free(CW_CRYPT_CTX crypt_ctx);

/**
  @brief initializes the encryption context

  @param crypt_ctx[in]  A crypto context which was previously allocated by cw_crypt_new()
  @param mode[in]       block cipher mode
  @param flags[in]      operation flags: CW_CRYPT_ENCRYPT or CW_CRYPT_DECRYPT.
                        these flags can be combined with CW_CRYPT_NOPAD to disable
                        automatic padding
  @param key[in]        encryption/decryption key.
  @param klen[in]       key length. Only 16, 24 and 32 bit keys are supported.
  @param iv[in]         initialization vector. When using GCM mode this vector will contain
                        also the authentication data (beginning at offset 13)
  @param ivlen[in]      length of initialization vector                 
  @return               CW_CRYPT_OK on success
                        CW_CRYPT_EINVCTX if crypto context is invalid or NULL
                        CW_CRYPT_EINVKEY if an invalid key was used
                        CW_CRYPT_EINVIV if an invalid initalization vector was used
                        CW_CRYPT_ENOMEM if not enough memory was available
                        CW_CRYPT_BADDATA if the encryption or decryption operation failed
*/
int cw_crypt_init(CW_CRYPT_CTX crypt_ctx,
                  enum ma_aes_mode mode,
                  int flags,
                  const unsigned char *key,
                  unsigned int key_len,
                  const unsigned char *iv,
                  unsigned int iv_len);

/**
  @brief perform encryption or decryption operation. The mode depends on the mode flag
         which was previously passed to cw_crypt_init function.

  @param crypt_ctx      A crypto context buffer which was previously allocated by cw_crypt_new()
  @param src[in]        depending on flags this buffer contains cleartext or ciphertext
                        data
  @param slen[in]       length of buffer
  @param dst[out]       destination buffer which contains result of crypt operation
  @param dlen[out]      final length of destination buffer after crypt operation

  @return               CW_CRYPT_OK on success
                        CW_CRYPT_EINVKEY if an invalid key was used
                        CW_CRYPT_EINVIV if an invalid initalization vector was used
                        CW_CRYPT_ENOMEM if not enough memory was available
                        CW_CRYPT_BADDATA if the encryption or decryption operation failed
*/                        
int cw_crypt_update(CW_CRYPT_CTX crypt_ctx,
                    const unsigned char *src,
                    unsigned int slen,
                    unsigned char *dst,
                    unsigned int *dlen);

/**
  @brief finishes encryption or decryption operation.

  @param crypt_ctx      A crypto context buffer which was previously allocated by cw_crypt_new()
  @param dst[out]       destination buffer which contains result of crypt operation. This value is
                        usually the destination buffer passed to cw_crypt_update plus the length
                        returned by cw_crypt_update.
  @param dlen[out]      final length of destination buffer after crypt operation

  @return               CW_CRYPT_OK on success
                        CW_CRYPT_EINVKEY if an invalid key was used
                        CW_CRYPT_EINVIV if an invalid initalization vector was used
                        CW_CRYPT_ENOMEM if not enough memory was available
                        CW_CRYPT_BADDATA if the encryption or decryption operation failed
*/
int cw_crypt_finish(CW_CRYPT_CTX crypt_ctx,
                    unsigned char *dst,
                    unsigned int *dlen);
/**
  @brief encrypts or decrypts a buffer in one step

  @param mode[in]       block cipher mode
  @param flags[in]      operation flags: CW_CRYPT_ENCRYPT or CW_CRYPT_DECRYPT.
                        these flags can be combined with CW_CRYPT_NOPAD to disable
                        automatic padding
  @param src[in]        depending on flags this buffer contains cleartext or ciphertext
                        data
  @param slen[in]       length of buffer
  @param dst[out]       destination buffer which contains result of crypt operation
  @param dlen[out]      final length of destination buffer after crypt operation
  @param key[in]        encryption/decryption key.
  @param klen[in]       key length. Only 16, 24 and 32 bit keys are supported.
  @param iv[in]         initialization vector. When using GCM mode this vector will contain
                        also the authentication data (beginning at offset 13)
  @param ivlen[in]      length of initialization vector                 
  @return               CW_CRYPT_OK on success
                        CW_CRYPT_EINVKEY if an invalid key was used
                        CW_CRYPT_EINVIV if an invalid initalization vector was used
                        CW_CRYPT_ENOMEM if not enough memory was available
                        CW_CRYPT_BADDATA if the encryption or decryption operation failed
*/
int cw_crypt(enum ma_aes_mode mode,
             int flags,
             const unsigned char *src,
             unsigned int slen,
             unsigned char *dst,
             unsigned int *dlen,
             const unsigned char *key,
             unsigned int klen,
             const unsigned char *iv,
             unsigned int ivlen);
#ifdef __cplusplus
}
#endif
#endif /* _cw_crypt_h */
