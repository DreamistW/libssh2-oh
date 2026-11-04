/*
 * Copyright (c) 2026 HomoXterm contributors.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBSSH2_OHCRYPTO_H
#define LIBSSH2_OHCRYPTO_H

#include <CryptoArchitectureKit/crypto_architecture_kit.h>
#include <CryptoArchitectureKit/crypto_key_agreement.h>
#include <stdbool.h>

#define LIBSSH2_CRYPTO_ENGINE libssh2_ohcrypto

#define LIBSSH2_MD5 0
#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES_CBC 0
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_AES_GCM 1
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 0
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 0

#define LIBSSH2_RSA 1
#define LIBSSH2_RSA_SHA1 1
#define LIBSSH2_RSA_SHA2 1
#define LIBSSH2_DSA 0
#define LIBSSH2_ECDSA 1
#define LIBSSH2_ED25519 1

#include "crypto_config.h"

#define EC_MAX_POINT_LEN 133

typedef enum {
    LIBSSH2_EC_CURVE_NISTP256 = 1,
    LIBSSH2_EC_CURVE_NISTP384 = 2,
    LIBSSH2_EC_CURVE_NISTP521 = 3
} libssh2_curve_type;

typedef struct {
    OH_CryptoAsymKeyGenerator *generator;
    OH_CryptoKeyPair *key_pair;
    libssh2_curve_type curve_type;
} _libssh2_ohcrypto_asym_ctx;

#define libssh2_rsa_ctx _libssh2_ohcrypto_asym_ctx
#define libssh2_ecdsa_ctx _libssh2_ohcrypto_asym_ctx
#define libssh2_ed25519_ctx _libssh2_ohcrypto_asym_ctx
#define _libssh2_ec_key _libssh2_ohcrypto_asym_ctx
#define _libssh2_rsa_free(ctx) _libssh2_ohcrypto_asym_free((ctx))
#define _libssh2_ecdsa_free(ctx) _libssh2_ohcrypto_asym_free((ctx))
#define _libssh2_ed25519_free(ctx) _libssh2_ohcrypto_asym_free((ctx))

#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

#define libssh2_crypto_init() 0
#define libssh2_crypto_exit() ((void)0)
#define _libssh2_random(buf, len) _libssh2_ohcrypto_random((buf), (len))
#define libssh2_prepare_iovec(vec, len) ((void)0)

typedef struct {
    OH_CryptoDigest *handle;
    size_t output_len;
} _libssh2_ohcrypto_digest_ctx;

#define libssh2_sha1_ctx _libssh2_ohcrypto_digest_ctx
#define libssh2_sha256_ctx _libssh2_ohcrypto_digest_ctx
#define libssh2_sha384_ctx _libssh2_ohcrypto_digest_ctx
#define libssh2_sha512_ctx _libssh2_ohcrypto_digest_ctx

#define libssh2_sha1_init(ctx) _libssh2_ohcrypto_digest_init((ctx), "SHA1", SHA_DIGEST_LENGTH)
#define libssh2_sha256_init(ctx) _libssh2_ohcrypto_digest_init((ctx), "SHA256", SHA256_DIGEST_LENGTH)
#define libssh2_sha384_init(ctx) _libssh2_ohcrypto_digest_init((ctx), "SHA384", SHA384_DIGEST_LENGTH)
#define libssh2_sha512_init(ctx) _libssh2_ohcrypto_digest_init((ctx), "SHA512", SHA512_DIGEST_LENGTH)
#define libssh2_sha1_update(ctx, data, len) _libssh2_ohcrypto_digest_update(&(ctx), (data), (len))
#define libssh2_sha256_update(ctx, data, len) _libssh2_ohcrypto_digest_update(&(ctx), (data), (len))
#define libssh2_sha384_update(ctx, data, len) _libssh2_ohcrypto_digest_update(&(ctx), (data), (len))
#define libssh2_sha512_update(ctx, data, len) _libssh2_ohcrypto_digest_update(&(ctx), (data), (len))
#define libssh2_sha1_final(ctx, out) _libssh2_ohcrypto_digest_final(&(ctx), (out))
#define libssh2_sha256_final(ctx, out) _libssh2_ohcrypto_digest_final(&(ctx), (out))
#define libssh2_sha384_final(ctx, out) _libssh2_ohcrypto_digest_final(&(ctx), (out))
#define libssh2_sha512_final(ctx, out) _libssh2_ohcrypto_digest_final(&(ctx), (out))
#define libssh2_sha1(data, len, out) _libssh2_ohcrypto_digest((data), (len), "SHA1", (out), SHA_DIGEST_LENGTH)
#define libssh2_sha256(data, len, out) _libssh2_ohcrypto_digest((data), (len), "SHA256", (out), SHA256_DIGEST_LENGTH)
#define libssh2_sha384(data, len, out) _libssh2_ohcrypto_digest((data), (len), "SHA384", (out), SHA384_DIGEST_LENGTH)
#define libssh2_sha512(data, len, out) _libssh2_ohcrypto_digest((data), (len), "SHA512", (out), SHA512_DIGEST_LENGTH)

typedef struct {
    OH_CryptoSymKeyGenerator *generator;
    OH_CryptoSymKey *key;
    OH_CryptoMac *handle;
    size_t output_len;
} libssh2_hmac_ctx;

typedef struct {
    const char *name;
    size_t key_len;
} _libssh2_ohcrypto_cipher_type;

typedef struct {
    OH_CryptoSymKeyGenerator *generator;
    OH_CryptoSymKey *key;
    OH_CryptoSymCipherParams *params;
    OH_CryptoSymCipher *handle;
    unsigned char nonce[12];
    bool gcm;
    bool exhausted;
} _libssh2_cipher_ctx;

#define _libssh2_cipher_type(name) _libssh2_ohcrypto_cipher_type name
#define _libssh2_cipher_aes128ctr { "AES128|CTR|NoPadding", 16 }
#define _libssh2_cipher_aes192ctr { "AES192|CTR|NoPadding", 24 }
#define _libssh2_cipher_aes256ctr { "AES256|CTR|NoPadding", 32 }
#define _libssh2_cipher_aes128gcm { "AES128|GCM|NoPadding", 16 }
#define _libssh2_cipher_aes256gcm { "AES256|GCM|NoPadding", 32 }
#define _libssh2_cipher_chacha20 { NULL, 0 }

#define _libssh2_cipher_init(ctx, type, iv, secret, encrypt) \
    _libssh2_ohcrypto_cipher_init(ctx, type, iv, secret, encrypt)
#define _libssh2_cipher_crypt(ctx, type, encrypt, block, len, firstlast) \
    _libssh2_ohcrypto_cipher_crypt(ctx, type, encrypt, block, len, firstlast)
#define _libssh2_cipher_dtor(ctx) _libssh2_ohcrypto_cipher_dtor((ctx))

typedef struct {
    unsigned char *data;
    size_t length;
} _libssh2_bn;

#define _libssh2_bn_ctx int
#define _libssh2_bn_ctx_new() 0
#define _libssh2_bn_ctx_free(ctx) ((void)0)
#define _libssh2_bn_init() _libssh2_ohcrypto_bn_init()
#define _libssh2_bn_init_from_bin() _libssh2_ohcrypto_bn_init()
#define _libssh2_bn_set_word(bn, word) _libssh2_ohcrypto_bn_set_word((bn), (word))
#define _libssh2_bn_from_bin(bn, len, data) _libssh2_ohcrypto_bn_from_bin((bn), (len), (data))
#define _libssh2_bn_to_bin(bn, data) _libssh2_ohcrypto_bn_to_bin((bn), (data))
#define _libssh2_bn_bytes(bn) ((bn)->length)
#define _libssh2_bn_bits(bn) _libssh2_ohcrypto_bn_bits((bn))
#define _libssh2_bn_free(bn) _libssh2_ohcrypto_bn_free((bn))

#define LIBSSH2_DH_GEX_MINGROUP 2048
#define LIBSSH2_DH_GEX_OPTGROUP 4096
#define LIBSSH2_DH_GEX_MAXGROUP 8192
#define LIBSSH2_DH_MAX_MODULUS_BITS 8192

typedef struct {
    /* 保存协商的实际 p/g 参数，固定组与 GEX 共用同一路径。 */
    OH_CryptoAsymKeySpec *params;
    OH_CryptoKeyPair *key_pair;
    _libssh2_bn prime;
} _libssh2_dh_ctx;

#define libssh2_dh_init(ctx) _libssh2_ohcrypto_dh_init((ctx))
#define libssh2_dh_key_pair(ctx, pub, g, p, order, bnctx) \
    _libssh2_ohcrypto_dh_key_pair((ctx), (pub), (g), (p), (order))
#define libssh2_dh_secret(ctx, secret, peer, p, bnctx) \
    _libssh2_ohcrypto_dh_secret((ctx), (secret), (peer), (p))
#define libssh2_dh_dtor(ctx) _libssh2_ohcrypto_dh_dtor((ctx))

int _libssh2_ohcrypto_random(void *buffer, size_t length);
int _libssh2_ohcrypto_digest_init(_libssh2_ohcrypto_digest_ctx *ctx,
                                  const char *algorithm, size_t output_len);
int _libssh2_ohcrypto_digest_update(_libssh2_ohcrypto_digest_ctx *ctx,
                                    const void *data, size_t length);
int _libssh2_ohcrypto_digest_final(_libssh2_ohcrypto_digest_ctx *ctx,
                                   unsigned char *output);
int _libssh2_ohcrypto_digest(const void *data, size_t length,
                             const char *algorithm, unsigned char *output,
                             size_t output_len);
int _libssh2_ohcrypto_cipher_init(_libssh2_cipher_ctx *ctx,
                                  _libssh2_ohcrypto_cipher_type type,
                                  unsigned char *iv, unsigned char *secret,
                                  int encrypt);
int _libssh2_ohcrypto_cipher_crypt(_libssh2_cipher_ctx *ctx,
                                   _libssh2_ohcrypto_cipher_type type,
                                   int encrypt, unsigned char *block,
                                   size_t block_len, int firstlast);
void _libssh2_ohcrypto_cipher_dtor(_libssh2_cipher_ctx *ctx);

_libssh2_bn *_libssh2_ohcrypto_bn_init(void);
int _libssh2_ohcrypto_bn_set_word(_libssh2_bn *bn, unsigned long word);
int _libssh2_ohcrypto_bn_from_bin(_libssh2_bn *bn, size_t length,
                                  const unsigned char *data);
int _libssh2_ohcrypto_bn_to_bin(const _libssh2_bn *bn, unsigned char *data);
size_t _libssh2_ohcrypto_bn_bits(const _libssh2_bn *bn);
void _libssh2_ohcrypto_bn_free(_libssh2_bn *bn);

void _libssh2_ohcrypto_dh_init(_libssh2_dh_ctx *ctx);
int _libssh2_ohcrypto_dh_key_pair(_libssh2_dh_ctx *ctx, _libssh2_bn *public_key,
                                  const _libssh2_bn *generator,
                                  const _libssh2_bn *prime, int group_order);
int _libssh2_ohcrypto_dh_secret(_libssh2_dh_ctx *ctx, _libssh2_bn *secret,
                                const _libssh2_bn *peer_public,
                                const _libssh2_bn *prime);
void _libssh2_ohcrypto_dh_dtor(_libssh2_dh_ctx *ctx);

void _libssh2_ohcrypto_asym_free(_libssh2_ohcrypto_asym_ctx *ctx);

#endif /* LIBSSH2_OHCRYPTO_H */
