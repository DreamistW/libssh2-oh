/*
 * Copyright (c) 2026 HomoXterm contributors.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef LIBSSH2_CRYPTO_C

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <hilog/log.h>

#define OHCRYPTO_LOG_DOMAIN 0xD003201
#define OHCRYPTO_LOG_TAG "HomoxLibssh2Crypto"

typedef struct {
    unsigned char *data;
    size_t length;
} oh_der_blob;

static Crypto_DataBlob oh_view(const void *data, size_t length)
{
    Crypto_DataBlob blob;
    blob.data = (unsigned char *)data;
    blob.len = length;
    return blob;
}

static void oh_digest_destroy(_libssh2_ohcrypto_digest_ctx *ctx)
{
    if(ctx != NULL && ctx->handle != NULL) {
        OH_DigestCrypto_Destroy(ctx->handle);
        ctx->handle = NULL;
    }
}

int _libssh2_ohcrypto_random(void *buffer, size_t length)
{
    OH_CryptoRand *random = NULL;
    Crypto_DataBlob output = {NULL, 0};
    OH_Crypto_ErrCode code;
    if(buffer == NULL || length == 0 || length > INT_MAX) {
        return -1;
    }
    code = OH_CryptoRand_Create(&random);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoRand_GenerateRandom(random, (int)length, &output);
    }
    if(code == CRYPTO_SUCCESS && output.len == length) {
        memcpy(buffer, output.data, length);
    }
    else {
        code = CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoRand_Destroy(random);
    return code == CRYPTO_SUCCESS ? 0 : -1;
}

int _libssh2_ohcrypto_digest_init(_libssh2_ohcrypto_digest_ctx *ctx,
                                  const char *algorithm, size_t output_len)
{
    if(ctx == NULL) {
        return 0;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->output_len = output_len;
    return OH_CryptoDigest_Create(algorithm, &ctx->handle) == CRYPTO_SUCCESS;
}

int _libssh2_ohcrypto_digest_update(_libssh2_ohcrypto_digest_ctx *ctx,
                                    const void *data, size_t length)
{
    Crypto_DataBlob input;
    if(ctx == NULL || ctx->handle == NULL || (data == NULL && length != 0)) {
        return 0;
    }
    input = oh_view(data, length);
    return OH_CryptoDigest_Update(ctx->handle, &input) == CRYPTO_SUCCESS;
}

int _libssh2_ohcrypto_digest_final(_libssh2_ohcrypto_digest_ctx *ctx,
                                   unsigned char *output)
{
    Crypto_DataBlob result = {NULL, 0};
    OH_Crypto_ErrCode code;
    if(ctx == NULL || ctx->handle == NULL || output == NULL) {
        return 0;
    }
    code = OH_CryptoDigest_Final(ctx->handle, &result);
    if(code == CRYPTO_SUCCESS && result.len == ctx->output_len) {
        memcpy(output, result.data, result.len);
    }
    else {
        code = CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_FreeDataBlob(&result);
    oh_digest_destroy(ctx);
    return code == CRYPTO_SUCCESS;
}

int _libssh2_ohcrypto_digest(const void *data, size_t length,
                             const char *algorithm, unsigned char *output,
                             size_t output_len)
{
    _libssh2_ohcrypto_digest_ctx ctx;
    if(!_libssh2_ohcrypto_digest_init(&ctx, algorithm, output_len)) {
        return -1;
    }
    if(!_libssh2_ohcrypto_digest_update(&ctx, data, length) ||
       !_libssh2_ohcrypto_digest_final(&ctx, output)) {
        oh_digest_destroy(&ctx);
        return -1;
    }
    return 0;
}

int _libssh2_hmac_ctx_init(libssh2_hmac_ctx *ctx)
{
    if(ctx == NULL) {
        return 0;
    }
    memset(ctx, 0, sizeof(*ctx));
    return 1;
}

static int oh_hmac_init(libssh2_hmac_ctx *ctx, const char *digest,
                        size_t output_len, void *key, size_t key_len)
{
    char key_algorithm[32];
    Crypto_DataBlob key_blob;
    Crypto_DataBlob digest_blob;
    OH_Crypto_ErrCode code;
    int written;
    if(ctx == NULL || digest == NULL || key == NULL || key_len == 0) {
        return 0;
    }
    written = snprintf(key_algorithm, sizeof(key_algorithm), "HMAC|%s", digest);
    if(written < 0 || (size_t)written >= sizeof(key_algorithm)) {
        return 0;
    }
    key_blob = oh_view(key, key_len);
    digest_blob = oh_view(digest, strlen(digest));
    code = OH_CryptoSymKeyGenerator_Create(key_algorithm, &ctx->generator);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymKeyGenerator_Convert(ctx->generator, &key_blob, &ctx->key);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Create("HMAC", &ctx->handle);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_SetParam(ctx->handle, CRYPTO_MAC_DIGEST_NAME_STR, &digest_blob);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Init(ctx->handle, ctx->key);
    }
    ctx->output_len = output_len;
    if(code != CRYPTO_SUCCESS) {
        _libssh2_hmac_cleanup(ctx);
        return 0;
    }
    return 1;
}

int _libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx, void *key, size_t key_len)
{
    return oh_hmac_init(ctx, "SHA1", SHA_DIGEST_LENGTH, key, key_len);
}

int _libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx, void *key, size_t key_len)
{
    return oh_hmac_init(ctx, "SHA256", SHA256_DIGEST_LENGTH, key, key_len);
}

int _libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx, void *key, size_t key_len)
{
    return oh_hmac_init(ctx, "SHA512", SHA512_DIGEST_LENGTH, key, key_len);
}

int _libssh2_hmac_update(libssh2_hmac_ctx *ctx, const void *data, size_t length)
{
    Crypto_DataBlob input;
    if(ctx == NULL || ctx->handle == NULL || (data == NULL && length != 0)) {
        return 0;
    }
    input = oh_view(data, length);
    return OH_CryptoMac_Update(ctx->handle, &input) == CRYPTO_SUCCESS;
}

int _libssh2_hmac_final(libssh2_hmac_ctx *ctx, void *data)
{
    Crypto_DataBlob output = {NULL, 0};
    OH_Crypto_ErrCode code;
    if(ctx == NULL || ctx->handle == NULL || data == NULL) {
        return 0;
    }
    code = OH_CryptoMac_Final(ctx->handle, &output);
    if(code == CRYPTO_SUCCESS && output.len == ctx->output_len) {
        memcpy(data, output.data, output.len);
    }
    else {
        code = CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_FreeDataBlob(&output);
    return code == CRYPTO_SUCCESS;
}

void _libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx)
{
    if(ctx == NULL) {
        return;
    }
    OH_CryptoMac_Destroy(ctx->handle);
    OH_CryptoSymKey_Destroy(ctx->key);
    OH_CryptoSymKeyGenerator_Destroy(ctx->generator);
    memset(ctx, 0, sizeof(*ctx));
}

int _libssh2_ohcrypto_cipher_init(_libssh2_cipher_ctx *ctx,
                                  _libssh2_ohcrypto_cipher_type type,
                                  unsigned char *iv, unsigned char *secret,
                                  int encrypt)
{
    char key_algorithm[16];
    Crypto_DataBlob key_blob;
    Crypto_DataBlob iv_blob;
    OH_Crypto_ErrCode code;
    int written;
    if(ctx == NULL || type.name == NULL || iv == NULL || secret == NULL) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    written = snprintf(key_algorithm, sizeof(key_algorithm), "AES%u",
                       (unsigned int)(type.key_len * 8));
    if(written < 0 || (size_t)written >= sizeof(key_algorithm)) {
        return -1;
    }
    key_blob = oh_view(secret, type.key_len);
    ctx->gcm = strstr(type.name, "|GCM|") != NULL;
    code = OH_CryptoSymKeyGenerator_Create(key_algorithm, &ctx->generator);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymKeyGenerator_Convert(ctx->generator, &key_blob, &ctx->key);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipherParams_Create(&ctx->params);
    }
    if(code == CRYPTO_SUCCESS) {
        if(ctx->gcm) {
            memcpy(ctx->nonce, iv, sizeof(ctx->nonce));
            return 0;
        }
        iv_blob = oh_view(iv, 16);
        code = OH_CryptoSymCipherParams_SetParam(ctx->params, CRYPTO_IV_DATABLOB, &iv_blob);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipher_Create(type.name, &ctx->handle);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipher_Init(ctx->handle,
            encrypt ? CRYPTO_ENCRYPT_MODE : CRYPTO_DECRYPT_MODE, ctx->key, ctx->params);
    }
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_cipher_dtor(ctx);
        return -1;
    }
    return 0;
}

/* RFC 5647: 包长度为 AAD；认证成功后才把完整明文交回 transport。 */
static int oh_gcm_packet(_libssh2_cipher_ctx *ctx, const char *name, int encrypt,
                         unsigned char *packet, size_t length)
{
    const size_t aad_len = 4, tag_len = 16;
    unsigned char empty_tag[16] = {0};
    OH_CryptoSymCipher *cipher = NULL;
    Crypto_DataBlob output = {NULL, 0};
    if(!packet || ctx->exhausted || length < aad_len || length > MAX_SSH_PACKET_LEN)
        return -1;
    /* 发送长度含长度字段，接收长度仅含密文；外层已为 tag 预留空间。 */
    size_t payload_len = encrypt ? length - aad_len : length;
    if(payload_len != _libssh2_ntohu32(packet) ||
       payload_len > MAX_SSH_PACKET_LEN - aad_len - tag_len)
        return -1;
    Crypto_DataBlob iv = oh_view(ctx->nonce, sizeof(ctx->nonce));
    Crypto_DataBlob aad = oh_view(packet, aad_len);
    Crypto_DataBlob input = oh_view(packet + aad_len, payload_len);
    Crypto_DataBlob tag = oh_view(encrypt ? empty_tag : packet + aad_len + payload_len, tag_len);
    size_t expected = payload_len + (encrypt ? tag_len : 0);
    int rc = -1;
    if(OH_CryptoSymCipherParams_SetParam(ctx->params, CRYPTO_IV_DATABLOB, &iv) == CRYPTO_SUCCESS &&
       OH_CryptoSymCipherParams_SetParam(ctx->params, CRYPTO_AAD_DATABLOB, &aad) == CRYPTO_SUCCESS &&
       OH_CryptoSymCipherParams_SetParam(ctx->params, CRYPTO_TAG_DATABLOB, &tag) == CRYPTO_SUCCESS &&
       OH_CryptoSymCipher_Create(name, &cipher) == CRYPTO_SUCCESS &&
       OH_CryptoSymCipher_Init(cipher, encrypt ? CRYPTO_ENCRYPT_MODE : CRYPTO_DECRYPT_MODE,
                               ctx->key, ctx->params) == CRYPTO_SUCCESS &&
       OH_CryptoSymCipher_Final(cipher, &input, &output) == CRYPTO_SUCCESS &&
       output.data && output.len == expected) {
        memcpy(encrypt ? packet + aad_len : packet, output.data, output.len);
        rc = 0;
    }
    if(output.data && !encrypt)
        _libssh2_explicit_zero(output.data, output.len);
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoSymCipher_Destroy(cipher);
    /* nonce 前四字节固定，后八字节按网络字节序递增；失败后禁止复用。 */
    ctx->exhausted = true;
    if(rc == 0) {
        for(size_t i = sizeof(ctx->nonce); i > 4; --i) {
            if(++ctx->nonce[i - 1] != 0) {
                ctx->exhausted = false;
                break;
            }
        }
    }
    return rc;
}

int _libssh2_ohcrypto_cipher_crypt(_libssh2_cipher_ctx *ctx,
                                   _libssh2_ohcrypto_cipher_type type,
                                   int encrypt, unsigned char *block,
                                   size_t block_len, int firstlast)
{
    Crypto_DataBlob input;
    Crypto_DataBlob output = {NULL, 0};
    OH_Crypto_ErrCode code;
    (void)firstlast;
    if(ctx && ctx->gcm)
        return oh_gcm_packet(ctx, type.name, encrypt, block, block_len);
    if(ctx == NULL || ctx->handle == NULL || block == NULL) {
        return -1;
    }
    input = oh_view(block, block_len);
    code = OH_CryptoSymCipher_Update(ctx->handle, &input, &output);
    if(code == CRYPTO_SUCCESS && output.len == block_len) {
        memcpy(block, output.data, block_len);
    }
    else {
        code = CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_FreeDataBlob(&output);
    return code == CRYPTO_SUCCESS ? 0 : -1;
}

void _libssh2_ohcrypto_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    Crypto_DataBlob output = {NULL, 0};
    if(ctx == NULL) {
        return;
    }
    if(ctx->handle != NULL) {
        (void)OH_CryptoSymCipher_Final(ctx->handle, NULL, &output);
        OH_Crypto_FreeDataBlob(&output);
    }
    OH_CryptoSymCipher_Destroy(ctx->handle);
    OH_CryptoSymCipherParams_Destroy(ctx->params);
    OH_CryptoSymKey_Destroy(ctx->key);
    OH_CryptoSymKeyGenerator_Destroy(ctx->generator);
    memset(ctx, 0, sizeof(*ctx));
}

_libssh2_bn *_libssh2_ohcrypto_bn_init(void)
{
    return (_libssh2_bn *)calloc(1, sizeof(_libssh2_bn));
}

static void oh_bn_clear(_libssh2_bn *bn)
{
    if(bn != NULL && bn->data != NULL) {
        _libssh2_explicit_zero(bn->data, bn->length);
        free(bn->data);
        bn->data = NULL;
        bn->length = 0;
    }
}

int _libssh2_ohcrypto_bn_from_bin(_libssh2_bn *bn, size_t length,
                                  const unsigned char *data)
{
    size_t offset = 0;
    unsigned char *copy;
    if(bn == NULL || (data == NULL && length != 0)) {
        return -1;
    }
    while(offset < length && data[offset] == 0) {
        ++offset;
    }
    length -= offset;
    copy = length == 0 ? NULL : (unsigned char *)malloc(length);
    if(length != 0 && copy == NULL) {
        return -1;
    }
    if(length != 0) {
        memcpy(copy, data + offset, length);
    }
    oh_bn_clear(bn);
    bn->data = copy;
    bn->length = length;
    return 0;
}

int _libssh2_ohcrypto_bn_set_word(_libssh2_bn *bn, unsigned long word)
{
    unsigned char data[sizeof(unsigned long)];
    size_t index;
    for(index = 0; index < sizeof(data); ++index) {
        data[sizeof(data) - index - 1] = (unsigned char)(word >> (index * 8));
    }
    return _libssh2_ohcrypto_bn_from_bin(bn, sizeof(data), data);
}

int _libssh2_ohcrypto_bn_to_bin(const _libssh2_bn *bn, unsigned char *data)
{
    if(bn == NULL || data == NULL) {
        return -1;
    }
    if(bn->length != 0) {
        memcpy(data, bn->data, bn->length);
    }
    return 0;
}

size_t _libssh2_ohcrypto_bn_bits(const _libssh2_bn *bn)
{
    unsigned char first;
    size_t bits;
    if(bn == NULL || bn->length == 0) {
        return 0;
    }
    first = bn->data[0];
    bits = (bn->length - 1) * 8;
    while(first != 0) {
        ++bits;
        first >>= 1;
    }
    return bits;
}

void _libssh2_ohcrypto_bn_free(_libssh2_bn *bn)
{
    if(bn != NULL) {
        oh_bn_clear(bn);
        free(bn);
    }
}

static size_t oh_der_length_size(size_t length)
{
    size_t bytes = 1;
    if(length < 128) {
        return 1;
    }
    bytes = 0;
    while(length != 0) {
        ++bytes;
        length >>= 8;
    }
    return bytes + 1;
}

static size_t oh_der_write_length(unsigned char *output, size_t length)
{
    size_t bytes;
    size_t index;
    if(length < 128) {
        output[0] = (unsigned char)length;
        return 1;
    }
    bytes = oh_der_length_size(length) - 1;
    output[0] = (unsigned char)(0x80 | bytes);
    for(index = 0; index < bytes; ++index) {
        output[bytes - index] = (unsigned char)(length >> (index * 8));
    }
    return bytes + 1;
}

static oh_der_blob oh_der_wrap(unsigned char tag, const unsigned char *data,
                               size_t length)
{
    oh_der_blob result = {NULL, 0};
    size_t length_size = oh_der_length_size(length);
    result.length = 1 + length_size + length;
    result.data = (unsigned char *)malloc(result.length);
    if(result.data == NULL) {
        result.length = 0;
        return result;
    }
    result.data[0] = tag;
    (void)oh_der_write_length(result.data + 1, length);
    if(length != 0) {
        memcpy(result.data + 1 + length_size, data, length);
    }
    return result;
}

static oh_der_blob oh_der_join(unsigned char tag, const oh_der_blob *parts,
                               size_t count, int prefix_zero)
{
    oh_der_blob result = {NULL, 0};
    unsigned char *content;
    size_t content_length = prefix_zero ? 1 : 0;
    size_t offset = 0;
    size_t index;
    for(index = 0; index < count; ++index) {
        content_length += parts[index].length;
    }
    content = (unsigned char *)malloc(content_length);
    if(content == NULL) {
        return result;
    }
    if(prefix_zero) {
        content[offset++] = 0;
    }
    for(index = 0; index < count; ++index) {
        memcpy(content + offset, parts[index].data, parts[index].length);
        offset += parts[index].length;
    }
    result = oh_der_wrap(tag, content, content_length);
    _libssh2_explicit_zero(content, content_length);
    free(content);
    return result;
}

static oh_der_blob oh_der_integer(const _libssh2_bn *value)
{
    oh_der_blob result = {NULL, 0};
    unsigned char *content;
    size_t prefix;
    size_t length;
    if(value == NULL) {
        return result;
    }
    prefix = value->length == 0 || (value->data[0] & 0x80) != 0 ? 1 : 0;
    length = value->length + prefix;
    content = (unsigned char *)calloc(length == 0 ? 1 : length, 1);
    if(content == NULL) {
        return result;
    }
    if(value->length != 0) {
        memcpy(content + prefix, value->data, value->length);
    }
    result = oh_der_wrap(0x02, content, length);
    _libssh2_explicit_zero(content, length);
    free(content);
    return result;
}

static void oh_der_free(oh_der_blob *blob)
{
    if(blob != NULL) {
        if(blob->data != NULL) {
            _libssh2_explicit_zero(blob->data, blob->length);
        }
        free(blob->data);
        blob->data = NULL;
        blob->length = 0;
    }
}

static void oh_data_blob_clear(Crypto_DataBlob *blob)
{
    if(blob != NULL && blob->data != NULL) {
        _libssh2_explicit_zero(blob->data, blob->len);
    }
    OH_Crypto_FreeDataBlob(blob);
}

static oh_der_blob oh_der_integer_bytes(const unsigned char *data,
                                        size_t length)
{
    _libssh2_bn value;
    while(length > 0 && *data == 0) {
        ++data;
        --length;
    }
    value.data = (unsigned char *)data;
    value.length = length;
    return oh_der_integer(&value);
}

static oh_der_blob oh_der_spki(const unsigned char *algorithm,
                               size_t algorithm_length,
                               const unsigned char *public_key,
                               size_t public_key_length)
{
    oh_der_blob algorithm_blob;
    oh_der_blob public_value;
    oh_der_blob parts[2];
    unsigned char *bit_string_content;
    algorithm_blob.data = (unsigned char *)algorithm;
    algorithm_blob.length = algorithm_length;
    bit_string_content = (unsigned char *)malloc(public_key_length + 1);
    if(bit_string_content == NULL) {
        public_value.data = NULL;
        public_value.length = 0;
    }
    else {
        bit_string_content[0] = 0;
        memcpy(bit_string_content + 1, public_key, public_key_length);
        public_value = oh_der_wrap(0x03, bit_string_content, public_key_length + 1);
        free(bit_string_content);
    }
    parts[0] = algorithm_blob;
    parts[1] = public_value;
    algorithm_blob = oh_der_join(0x30, parts, 2, 0);
    oh_der_free(&public_value);
    return algorithm_blob;
}

static int oh_der_read_length(const unsigned char **cursor,
                              const unsigned char *end, size_t *length)
{
    size_t bytes;
    size_t value = 0;
    size_t index;
    if(cursor == NULL || *cursor == NULL || *cursor >= end || length == NULL) {
        return -1;
    }
    bytes = *(*cursor)++;
    if((bytes & 0x80) == 0) {
        *length = bytes;
        return (size_t)(end - *cursor) >= *length ? 0 : -1;
    }
    bytes &= 0x7f;
    if(bytes == 0 || bytes > sizeof(size_t) || (size_t)(end - *cursor) < bytes) {
        return -1;
    }
    for(index = 0; index < bytes; ++index) {
        value = (value << 8) | *(*cursor)++;
    }
    if((size_t)(end - *cursor) < value) {
        return -1;
    }
    *length = value;
    return 0;
}

static int oh_der_read_tlv(const unsigned char **cursor,
                           const unsigned char *end, unsigned char tag,
                           const unsigned char **value, size_t *length)
{
    if(cursor == NULL || *cursor == NULL || *cursor >= end || **cursor != tag) {
        return -1;
    }
    ++*cursor;
    if(oh_der_read_length(cursor, end, length) != 0) {
        return -1;
    }
    *value = *cursor;
    *cursor += *length;
    return 0;
}

static _libssh2_ohcrypto_asym_ctx *oh_asym_alloc(void)
{
    return (_libssh2_ohcrypto_asym_ctx *)calloc(1, sizeof(_libssh2_ohcrypto_asym_ctx));
}

void _libssh2_ohcrypto_asym_free(_libssh2_ohcrypto_asym_ctx *ctx)
{
    if(ctx == NULL) {
        return;
    }
    OH_CryptoKeyPair_Destroy(ctx->key_pair);
    OH_CryptoAsymKeyGenerator_Destroy(ctx->generator);
    _libssh2_explicit_zero(ctx, sizeof(*ctx));
    free(ctx);
}

static int oh_asym_import(_libssh2_ohcrypto_asym_ctx **out,
                          const char *algorithm, const unsigned char *data,
                          size_t data_length, const unsigned char *passphrase)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    Crypto_DataBlob private_blob;
    Crypto_EncodingType encoding;
    OH_Crypto_ErrCode code;
    size_t passphrase_length;
    if(out == NULL || algorithm == NULL || data == NULL || data_length == 0) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    encoding = data_length >= 10 && memcmp(data, "-----BEGIN", 10) == 0 ?
        CRYPTO_PEM : CRYPTO_DER;
    private_blob = oh_view(data, data_length);
    code = OH_CryptoAsymKeyGenerator_Create(algorithm, &ctx->generator);
    if(code == CRYPTO_SUCCESS && passphrase != NULL && passphrase[0] != 0) {
        passphrase_length = strlen((const char *)passphrase);
        if(passphrase_length > UINT32_MAX) {
            code = CRYPTO_PARAMETER_CHECK_FAILED;
        }
        else {
            code = OH_CryptoAsymKeyGenerator_SetPassword(
                ctx->generator, passphrase, (uint32_t)passphrase_length);
        }
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Convert(ctx->generator, encoding, NULL,
                                                 &private_blob, &ctx->key_pair);
    }
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_read_file(LIBSSH2_SESSION *session, const char *filename,
                        unsigned char **data, size_t *length)
{
    FILE *file;
    long file_length;
    unsigned char *buffer;
    if(filename == NULL || data == NULL || length == NULL) {
        return -1;
    }
    file = fopen(filename, "rb");
    if(file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if(file != NULL) {
            fclose(file);
        }
        return -1;
    }
    file_length = ftell(file);
    if(file_length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    buffer = (unsigned char *)LIBSSH2_ALLOC(session, (size_t)file_length);
    if(buffer == NULL) {
        fclose(file);
        return -1;
    }
    if(fread(buffer, 1, (size_t)file_length, file) != (size_t)file_length) {
        LIBSSH2_FREE(session, buffer);
        fclose(file);
        return -1;
    }
    fclose(file);
    *data = buffer;
    *length = (size_t)file_length;
    return 0;
}

static oh_der_blob oh_rsa_public_der(const unsigned char *exponent,
                                     size_t exponent_length,
                                     const unsigned char *modulus,
                                     size_t modulus_length)
{
    static const unsigned char algorithm[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    oh_der_blob integers[2];
    oh_der_blob public_sequence;
    oh_der_blob result;
    integers[0] = oh_der_integer_bytes(modulus, modulus_length);
    integers[1] = oh_der_integer_bytes(exponent, exponent_length);
    public_sequence = oh_der_join(0x30, integers, 2, 0);
    result = oh_der_spki(algorithm, sizeof(algorithm), public_sequence.data,
                         public_sequence.length);
    oh_der_free(&public_sequence);
    oh_der_free(&integers[1]);
    oh_der_free(&integers[0]);
    return result;
}

static int oh_asym_import_public(_libssh2_ohcrypto_asym_ctx **out,
                                 const char *algorithm,
                                 const oh_der_blob *public_der,
                                 libssh2_curve_type curve_type)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    Crypto_DataBlob public_blob;
    OH_Crypto_ErrCode code;
    if(out == NULL || public_der == NULL || public_der->data == NULL) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    public_blob = oh_view(public_der->data, public_der->length);
    ctx->curve_type = curve_type;
    code = OH_CryptoAsymKeyGenerator_Create(algorithm, &ctx->generator);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Convert(ctx->generator, CRYPTO_DER,
                                                 &public_blob, NULL,
                                                 &ctx->key_pair);
    }
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_openssh_rsa_private(libssh2_rsa_ctx **ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *filedata, size_t filedata_length,
                                  const unsigned char *passphrase);
static int oh_openssh_ecdsa_private(libssh2_ecdsa_ctx **ctx,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata, size_t filedata_length,
                                    const unsigned char *passphrase);
static int oh_openssh_ed25519_private(libssh2_ed25519_ctx **ctx,
                                      LIBSSH2_SESSION *session,
                                      const char *filedata, size_t filedata_length,
                                      const unsigned char *passphrase);

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
                     const unsigned char *edata, unsigned long elen,
                     const unsigned char *ndata, unsigned long nlen,
                     const unsigned char *ddata, unsigned long dlen,
                     const unsigned char *pdata, unsigned long plen,
                     const unsigned char *qdata, unsigned long qlen,
                     const unsigned char *e1data, unsigned long e1len,
                     const unsigned char *e2data, unsigned long e2len,
                     const unsigned char *coeffdata, unsigned long coefflen)
{
    oh_der_blob public_der;
    int result;
    (void)dlen;
    (void)pdata;
    (void)plen;
    (void)qdata;
    (void)qlen;
    (void)e1data;
    (void)e1len;
    (void)e2data;
    (void)e2len;
    (void)coeffdata;
    (void)coefflen;
    if(rsa == NULL || edata == NULL || elen == 0 || ndata == NULL || nlen == 0 ||
       ddata != NULL) {
        return -1;
    }
    public_der = oh_rsa_public_der(edata, (size_t)elen, ndata, (size_t)nlen);
    result = oh_asym_import_public(rsa, "RSA2048", &public_der,
                                   LIBSSH2_EC_CURVE_NISTP256);
    oh_der_free(&public_der);
    return result;
}

static const char *oh_rsa_sign_algorithm(size_t hash_length, int only_sign)
{
    if(hash_length == SHA_DIGEST_LENGTH) {
        return only_sign ? "RSA|PKCS1|SHA1|OnlySign" : "RSA|PKCS1|SHA1";
    }
    if(hash_length == SHA256_DIGEST_LENGTH) {
        return only_sign ? "RSA|PKCS1|SHA256|OnlySign" : "RSA|PKCS1|SHA256";
    }
    if(hash_length == SHA512_DIGEST_LENGTH) {
        return only_sign ? "RSA|PKCS1|SHA512|OnlySign" : "RSA|PKCS1|SHA512";
    }
    return NULL;
}

int _libssh2_rsa_sha2_verify(libssh2_rsa_ctx *rsa, size_t hash_length,
                             const unsigned char *signature,
                             size_t signature_length,
                             const unsigned char *message,
                             size_t message_length)
{
    OH_CryptoVerify *verify = NULL;
    Crypto_DataBlob message_blob;
    Crypto_DataBlob signature_blob;
    const char *algorithm = oh_rsa_sign_algorithm(hash_length, 0);
    OH_Crypto_ErrCode code;
    bool verified = false;
    if(rsa == NULL || rsa->key_pair == NULL || algorithm == NULL) {
        return -1;
    }
    message_blob = oh_view(message, message_length);
    signature_blob = oh_view(signature, signature_length);
    code = OH_CryptoVerify_Create(algorithm, &verify);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(rsa->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        verified = OH_CryptoVerify_Final(verify, &message_blob, &signature_blob);
    }
    OH_CryptoVerify_Destroy(verify);
    return code == CRYPTO_SUCCESS && verified ? 0 : -1;
}

int _libssh2_rsa_sha2_sign(LIBSSH2_SESSION *session, libssh2_rsa_ctx *rsa,
                           const unsigned char *hash, size_t hash_length,
                           unsigned char **signature, size_t *signature_length)
{
    OH_CryptoSign *sign = NULL;
    Crypto_DataBlob hash_blob;
    Crypto_DataBlob output = {NULL, 0};
    const char *algorithm = oh_rsa_sign_algorithm(hash_length, 1);
    OH_Crypto_ErrCode code;
    unsigned char *copy = NULL;
    if(session == NULL || rsa == NULL || rsa->key_pair == NULL ||
       signature == NULL || signature_length == NULL || algorithm == NULL) {
        return -1;
    }
    hash_blob = oh_view(hash, hash_length);
    code = OH_CryptoSign_Create(algorithm, &sign);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(rsa->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Final(sign, &hash_blob, &output);
    }
    if(code == CRYPTO_SUCCESS) {
        copy = (unsigned char *)LIBSSH2_ALLOC(session, output.len);
        if(copy == NULL) {
            code = CRYPTO_MEMORY_ERROR;
        }
        else {
            memcpy(copy, output.data, output.len);
        }
    }
    if(code == CRYPTO_SUCCESS) {
        *signature = copy;
        *signature_length = output.len;
    }
    else if(copy != NULL) {
        LIBSSH2_FREE(session, copy);
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoSign_Destroy(sign);
    return code == CRYPTO_SUCCESS ? 0 : -1;
}

/* 旧主机验签接收原始消息，公钥认证签名接收预哈希值。 */
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa, const unsigned char *sig,
                             size_t sig_len, const unsigned char *msg, size_t msg_len)
{
    return _libssh2_rsa_sha2_verify(rsa, SHA_DIGEST_LENGTH, sig, sig_len, msg, msg_len);
}

/* 老服务端可能不发送 server-sig-algs，签名时仍须核对会话的显式授权。 */
static bool oh_allows_rsa_sha1(const LIBSSH2_SESSION *session)
{
    const char *pref = session ? session->sign_algo_prefs : NULL;
    while(pref && *pref) {
        size_t len = strcspn(pref, ",");
        if(len == 7 && !memcmp(pref, "ssh-rsa", 7))
            return true;
        pref += len;
        if(*pref)
            ++pref;
    }
    return false;
}

int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session, libssh2_rsa_ctx *rsa,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char **sig, size_t *sig_len)
{
    if(hash_len != SHA_DIGEST_LENGTH || !oh_allows_rsa_sha1(session))
        return -1;
    return _libssh2_rsa_sha2_sign(session, rsa, hash, hash_len, sig, sig_len);
}

int _libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                        LIBSSH2_SESSION *session,
                                        const char *filedata,
                                        size_t filedata_length,
                                        const unsigned char *passphrase)
{
    static const char *algorithms[] = {"RSA2048", "RSA3072", "RSA4096", "RSA8192"};
    size_t index;
    int result = -1;
    for(index = 0; index < sizeof(algorithms) / sizeof(algorithms[0]); ++index) {
        result = oh_asym_import(rsa, algorithms[index],
                                (const unsigned char *)filedata,
                                filedata_length, passphrase);
        if(result == 0) {
            break;
        }
    }
    if(result != 0 && filedata_length >= 35 &&
       memcmp(filedata, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
        result = oh_openssh_rsa_private(rsa, session, filedata,
                                        filedata_length, passphrase);
    }
    return result;
}

int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa,
                             LIBSSH2_SESSION *session, const char *filename,
                             const unsigned char *passphrase)
{
    unsigned char *data = NULL;
    size_t length = 0;
    int result;
    if(oh_read_file(session, filename, &data, &length) != 0) {
        return -1;
    }
    result = _libssh2_rsa_new_private_frommemory(rsa, session,
                                                 (const char *)data, length,
                                                 passphrase);
    _libssh2_explicit_zero(data, length);
    LIBSSH2_FREE(session, data);
    return result;
}

static const char *oh_ecc_key_algorithm(libssh2_curve_type curve_type)
{
    if(curve_type == LIBSSH2_EC_CURVE_NISTP256) {
        return "ECC256";
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP384) {
        return "ECC384";
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP521) {
        return "ECC521";
    }
    return NULL;
}

static const char *oh_ecc_sign_algorithm(libssh2_curve_type curve_type,
                                         int only_sign)
{
    if(curve_type == LIBSSH2_EC_CURVE_NISTP256) {
        return only_sign ? "ECC|SHA256|OnlySign" : "ECC|SHA256";
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP384) {
        return only_sign ? "ECC|SHA384|OnlySign" : "ECC|SHA384";
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP521) {
        return only_sign ? "ECC|SHA512|OnlySign" : "ECC|SHA512";
    }
    return NULL;
}

static size_t oh_ecc_coordinate_length(libssh2_curve_type curve_type)
{
    if(curve_type == LIBSSH2_EC_CURVE_NISTP256) {
        return 32;
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP384) {
        return 48;
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP521) {
        return 66;
    }
    return 0;
}

static oh_der_blob oh_ecc_public_der(libssh2_curve_type curve_type,
                                     const unsigned char *point,
                                     size_t point_length)
{
    static const unsigned char p256_algorithm[] = {
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    static const unsigned char p384_algorithm[] = {
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
    };
    static const unsigned char p521_algorithm[] = {
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
    };
    if(curve_type == LIBSSH2_EC_CURVE_NISTP256) {
        return oh_der_spki(p256_algorithm, sizeof(p256_algorithm), point,
                           point_length);
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP384) {
        return oh_der_spki(p384_algorithm, sizeof(p384_algorithm), point,
                           point_length);
    }
    if(curve_type == LIBSSH2_EC_CURVE_NISTP521) {
        return oh_der_spki(p521_algorithm, sizeof(p521_algorithm), point,
                           point_length);
    }
    {
        oh_der_blob empty = {NULL, 0};
        return empty;
    }
}

libssh2_curve_type _libssh2_ecdsa_get_curve_type(libssh2_ecdsa_ctx *ctx)
{
    return ctx == NULL ? LIBSSH2_EC_CURVE_NISTP256 : ctx->curve_type;
}

int _libssh2_ecdsa_curve_type_from_name(const char *name,
                                        libssh2_curve_type *out_type)
{
    libssh2_curve_type type;
    if(name == NULL) {
        return -1;
    }
    if(strcmp(name, "ecdsa-sha2-nistp256") == 0) {
        type = LIBSSH2_EC_CURVE_NISTP256;
    }
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0) {
        type = LIBSSH2_EC_CURVE_NISTP384;
    }
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0) {
        type = LIBSSH2_EC_CURVE_NISTP521;
    }
    else {
        return -1;
    }
    if(out_type != NULL) {
        *out_type = type;
    }
    return 0;
}

int _libssh2_ecdsa_curve_name_with_octal_new(libssh2_ecdsa_ctx **ctx,
                                              const unsigned char *point,
                                              size_t point_length,
                                              libssh2_curve_type curve_type)
{
    oh_der_blob public_der;
    const char *algorithm = oh_ecc_key_algorithm(curve_type);
    int result;
    if(algorithm == NULL || point == NULL || point_length == 0) {
        return -1;
    }
    public_der = oh_ecc_public_der(curve_type, point, point_length);
    result = oh_asym_import_public(ctx, algorithm, &public_der, curve_type);
    oh_der_free(&public_der);
    return result;
}

static oh_der_blob oh_ecdsa_signature_der(const unsigned char *r,
                                          size_t r_length,
                                          const unsigned char *s,
                                          size_t s_length)
{
    oh_der_blob integers[2];
    oh_der_blob result;
    integers[0] = oh_der_integer_bytes(r, r_length);
    integers[1] = oh_der_integer_bytes(s, s_length);
    result = oh_der_join(0x30, integers, 2, 0);
    oh_der_free(&integers[1]);
    oh_der_free(&integers[0]);
    return result;
}

int _libssh2_ecdsa_verify(libssh2_ecdsa_ctx *ctx,
                          const unsigned char *r, size_t r_length,
                          const unsigned char *s, size_t s_length,
                          const unsigned char *message, size_t message_length)
{
    OH_CryptoVerify *verify = NULL;
    oh_der_blob signature_der;
    Crypto_DataBlob message_blob;
    Crypto_DataBlob signature_blob;
    const char *algorithm;
    OH_Crypto_ErrCode code;
    bool verified = false;
    if(ctx == NULL || ctx->key_pair == NULL) {
        return -1;
    }
    algorithm = oh_ecc_sign_algorithm(ctx->curve_type, 0);
    signature_der = oh_ecdsa_signature_der(r, r_length, s, s_length);
    if(algorithm == NULL || signature_der.data == NULL) {
        oh_der_free(&signature_der);
        return -1;
    }
    message_blob = oh_view(message, message_length);
    signature_blob = oh_view(signature_der.data, signature_der.length);
    code = OH_CryptoVerify_Create(algorithm, &verify);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(ctx->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        verified = OH_CryptoVerify_Final(verify, &message_blob, &signature_blob);
    }
    OH_CryptoVerify_Destroy(verify);
    oh_der_free(&signature_der);
    return code == CRYPTO_SUCCESS && verified ? 0 : -1;
}

static int oh_ecdsa_der_to_ssh(LIBSSH2_SESSION *session,
                               const Crypto_DataBlob *der,
                               unsigned char **signature,
                               size_t *signature_length)
{
    const unsigned char *cursor;
    const unsigned char *end;
    const unsigned char *sequence;
    const unsigned char *r;
    const unsigned char *s;
    size_t sequence_length;
    size_t r_length;
    size_t s_length;
    unsigned char *output;
    if(der == NULL || der->data == NULL || signature == NULL ||
       signature_length == NULL) {
        return -1;
    }
    cursor = der->data;
    end = der->data + der->len;
    if(oh_der_read_tlv(&cursor, end, 0x30, &sequence, &sequence_length) != 0 ||
       cursor != end) {
        return -1;
    }
    cursor = sequence;
    end = sequence + sequence_length;
    if(oh_der_read_tlv(&cursor, end, 0x02, &r, &r_length) != 0 ||
       oh_der_read_tlv(&cursor, end, 0x02, &s, &s_length) != 0 || cursor != end ||
       r_length > UINT32_MAX || s_length > UINT32_MAX) {
        return -1;
    }
    output = (unsigned char *)LIBSSH2_ALLOC(session, 8 + r_length + s_length);
    if(output == NULL) {
        return -1;
    }
    _libssh2_htonu32(output, (uint32_t)r_length);
    memcpy(output + 4, r, r_length);
    _libssh2_htonu32(output + 4 + r_length, (uint32_t)s_length);
    memcpy(output + 8 + r_length, s, s_length);
    *signature = output;
    *signature_length = 8 + r_length + s_length;
    return 0;
}

int _libssh2_ecdsa_sign(LIBSSH2_SESSION *session, libssh2_ecdsa_ctx *ctx,
                        const unsigned char *hash, size_t hash_length,
                        unsigned char **signature, size_t *signature_length)
{
    OH_CryptoSign *sign = NULL;
    Crypto_DataBlob hash_blob;
    Crypto_DataBlob output = {NULL, 0};
    const char *algorithm;
    OH_Crypto_ErrCode code;
    int result = -1;
    if(ctx == NULL || ctx->key_pair == NULL) {
        return -1;
    }
    algorithm = oh_ecc_sign_algorithm(ctx->curve_type, 1);
    hash_blob = oh_view(hash, hash_length);
    code = algorithm == NULL ? CRYPTO_NOT_SUPPORTED :
        OH_CryptoSign_Create(algorithm, &sign);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(ctx->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Final(sign, &hash_blob, &output);
    }
    if(code == CRYPTO_SUCCESS) {
        result = oh_ecdsa_der_to_ssh(session, &output, signature, signature_length);
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoSign_Destroy(sign);
    return result;
}

static libssh2_curve_type oh_detect_ecc_curve(OH_CryptoKeyPair *key_pair)
{
    Crypto_DataBlob x = {NULL, 0};
    libssh2_curve_type type = LIBSSH2_EC_CURVE_NISTP256;
    if(key_pair != NULL &&
       OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(key_pair),
                                CRYPTO_ECC_PK_X_DATABLOB, &x) == CRYPTO_SUCCESS) {
        if(x.len > 48) {
            type = LIBSSH2_EC_CURVE_NISTP521;
        }
        else if(x.len > 32) {
            type = LIBSSH2_EC_CURVE_NISTP384;
        }
    }
    OH_Crypto_FreeDataBlob(&x);
    return type;
}

int _libssh2_ecdsa_create_key(LIBSSH2_SESSION *session,
                              _libssh2_ec_key **out_private_key,
                              unsigned char **out_public_key,
                              size_t *out_public_key_length,
                              libssh2_curve_type curve_type)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    Crypto_DataBlob x = {NULL, 0};
    Crypto_DataBlob y = {NULL, 0};
    const char *algorithm = oh_ecc_key_algorithm(curve_type);
    size_t coordinate_length = oh_ecc_coordinate_length(curve_type);
    unsigned char *point = NULL;
    OH_Crypto_ErrCode code;
    if(session == NULL || out_private_key == NULL || out_public_key == NULL ||
       out_public_key_length == NULL || algorithm == NULL) {
        return -1;
    }
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    ctx->curve_type = curve_type;
    code = OH_CryptoAsymKeyGenerator_Create(algorithm, &ctx->generator);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(ctx->generator, &ctx->key_pair);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(ctx->key_pair),
                                        CRYPTO_ECC_PK_X_DATABLOB, &x);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(ctx->key_pair),
                                        CRYPTO_ECC_PK_Y_DATABLOB, &y);
    }
    if(code == CRYPTO_SUCCESS && (x.len > coordinate_length || y.len > coordinate_length)) {
        code = CRYPTO_OPERTION_ERROR;
    }
    if(code == CRYPTO_SUCCESS) {
        point = (unsigned char *)LIBSSH2_CALLOC(session, 1 + 2 * coordinate_length);
        if(point == NULL) {
            code = CRYPTO_MEMORY_ERROR;
        }
        else {
            point[0] = 4;
            memcpy(point + 1 + coordinate_length - x.len, x.data, x.len);
            memcpy(point + 1 + 2 * coordinate_length - y.len, y.data, y.len);
        }
    }
    OH_Crypto_FreeDataBlob(&x);
    OH_Crypto_FreeDataBlob(&y);
    if(code != CRYPTO_SUCCESS) {
        if(point != NULL) {
            LIBSSH2_FREE(session, point);
        }
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out_private_key = ctx;
    *out_public_key = point;
    *out_public_key_length = 1 + 2 * coordinate_length;
    return 0;
}

int _libssh2_ecdh_gen_k(_libssh2_bn **secret, _libssh2_ec_key *private_key,
                        const unsigned char *server_public_key,
                        size_t server_public_key_length)
{
    libssh2_ecdsa_ctx *peer = NULL;
    OH_CryptoKeyAgreement *agreement = NULL;
    Crypto_DataBlob shared = {NULL, 0};
    const char *algorithm;
    OH_Crypto_ErrCode code;
    int result = -1;
    if(secret == NULL || *secret == NULL || private_key == NULL) {
        return -1;
    }
    algorithm = oh_ecc_key_algorithm(private_key->curve_type);
    if(_libssh2_ecdsa_curve_name_with_octal_new(&peer, server_public_key,
                                                server_public_key_length,
                                                private_key->curve_type) != 0) {
        return -1;
    }
    code = OH_CryptoKeyAgreement_Create(algorithm, &agreement);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement,
            OH_CryptoKeyPair_GetPrivKey(private_key->key_pair),
            OH_CryptoKeyPair_GetPubKey(peer->key_pair), &shared);
    }
    if(code == CRYPTO_SUCCESS &&
       _libssh2_ohcrypto_bn_from_bin(*secret, shared.len, shared.data) == 0) {
        result = 0;
    }
    oh_data_blob_clear(&shared);
    OH_CryptoKeyAgreement_Destroy(agreement);
    _libssh2_ohcrypto_asym_free(peer);
    return result;
}

int _libssh2_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx **ctx,
                                          LIBSSH2_SESSION *session,
                                          const char *filedata,
                                          size_t filedata_length,
                                          const unsigned char *passphrase)
{
    static const char *algorithms[] = {"ECC256", "ECC384", "ECC521"};
    size_t index;
    int result;
    result = -1;
    for(index = 0; index < sizeof(algorithms) / sizeof(algorithms[0]); ++index) {
        result = oh_asym_import(ctx, algorithms[index],
                                (const unsigned char *)filedata,
                                filedata_length, passphrase);
        if(result == 0) {
            break;
        }
    }
    if(result != 0 && filedata_length >= 35 &&
       memcmp(filedata, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
        result = oh_openssh_ecdsa_private(ctx, session, filedata,
                                          filedata_length, passphrase);
    }
    if(result == 0) {
        (*ctx)->curve_type = oh_detect_ecc_curve((*ctx)->key_pair);
    }
    return result;
}

int _libssh2_ecdsa_new_private(libssh2_ecdsa_ctx **ctx,
                               LIBSSH2_SESSION *session, const char *filename,
                               const unsigned char *passphrase)
{
    unsigned char *data = NULL;
    size_t length = 0;
    int result;
    if(oh_read_file(session, filename, &data, &length) != 0) {
        return -1;
    }
    result = _libssh2_ecdsa_new_private_frommemory(ctx, session,
                                                   (const char *)data, length,
                                                   passphrase);
    _libssh2_explicit_zero(data, length);
    LIBSSH2_FREE(session, data);
    return result;
}

int _libssh2_ecdsa_new_private_sk(libssh2_ecdsa_ctx **ctx,
                                  unsigned char *flags,
                                  const char **application,
                                  const unsigned char **key_handle,
                                  size_t *handle_length,
                                  LIBSSH2_SESSION *session,
                                  const char *filename,
                                  const unsigned char *passphrase)
{
    (void)ctx; (void)flags; (void)application; (void)key_handle;
    (void)handle_length; (void)session; (void)filename; (void)passphrase;
    return -1;
}

int _libssh2_ecdsa_new_private_frommemory_sk(libssh2_ecdsa_ctx **ctx,
                                             unsigned char *flags,
                                             const char **application,
                                             const unsigned char **key_handle,
                                             size_t *handle_length,
                                             LIBSSH2_SESSION *session,
                                             const char *filedata,
                                             size_t filedata_length,
                                             const unsigned char *passphrase)
{
    (void)ctx; (void)flags; (void)application; (void)key_handle;
    (void)handle_length; (void)session; (void)filedata; (void)filedata_length;
    (void)passphrase;
    return -1;
}

static oh_der_blob oh_rfc8410_public_der(unsigned char oid_last,
                                         const unsigned char *raw_key,
                                         size_t raw_key_length)
{
    unsigned char algorithm[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x00};
    algorithm[sizeof(algorithm) - 1] = oid_last;
    return oh_der_spki(algorithm, sizeof(algorithm), raw_key, raw_key_length);
}

static int oh_raw_keypair(_libssh2_ohcrypto_asym_ctx **out,
                          const char *algorithm,
                          CryptoAsymKeySpec_Type spec_type,
                          CryptoAsymKey_ParamType param_type,
                          const unsigned char *raw, size_t raw_length)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    OH_CryptoAsymKeySpec *spec = NULL;
    OH_CryptoAsymKeyGeneratorWithSpec *generator = NULL;
    Crypto_DataBlob raw_blob;
    OH_Crypto_ErrCode code;
    if(out == NULL || raw == NULL || raw_length == 0) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    raw_blob = oh_view(raw, raw_length);
    code = OH_CryptoAsymKeySpec_Create(algorithm, spec_type, &spec);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, param_type, &raw_blob);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(spec, &generator);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(generator,
                                                             &ctx->key_pair);
    }
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(generator);
    OH_CryptoAsymKeySpec_Destroy(spec);
    if(code != CRYPTO_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, OHCRYPTO_LOG_DOMAIN, OHCRYPTO_LOG_TAG,
                     "raw-keypair %{public}s spec=%{public}d code=%{public}d",
                     algorithm, (int)spec_type, (int)code);
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_rsa_components_keypair(_libssh2_ohcrypto_asym_ctx **out,
                                     const unsigned char *modulus,
                                     size_t modulus_len,
                                     const unsigned char *exponent,
                                     size_t exponent_len,
                                     const unsigned char *private_exponent,
                                     size_t private_exponent_len)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    OH_CryptoAsymKeySpec *spec = NULL;
    OH_CryptoAsymKeyGeneratorWithSpec *generator = NULL;
    Crypto_DataBlob n = oh_view(modulus, modulus_len);
    Crypto_DataBlob e = oh_view(exponent, exponent_len);
    Crypto_DataBlob d = oh_view(private_exponent, private_exponent_len);
    OH_Crypto_ErrCode code;
    if(out == NULL || modulus == NULL || exponent == NULL ||
       private_exponent == NULL) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    code = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC,
                                       &spec);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_RSA_N_DATABLOB, &n);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_RSA_E_DATABLOB, &e);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_RSA_D_DATABLOB, &d);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(spec, &generator);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(generator,
                                                             &ctx->key_pair);
    }
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(generator);
    OH_CryptoAsymKeySpec_Destroy(spec);
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_ecc_components_keypair(_libssh2_ohcrypto_asym_ctx **out,
                                     libssh2_curve_type curve_type,
                                     const unsigned char *point,
                                     size_t point_len,
                                     const unsigned char *private_scalar,
                                     size_t private_scalar_len)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    OH_CryptoAsymKeySpec *spec = NULL;
    OH_CryptoAsymKeySpec *common = NULL;
    OH_CryptoAsymKeyGeneratorWithSpec *generator = NULL;
    const char *curve_name;
    size_t coordinate_len;
    Crypto_DataBlob x;
    Crypto_DataBlob y;
    Crypto_DataBlob sk = oh_view(private_scalar, private_scalar_len);
    OH_Crypto_ErrCode code;
    if(curve_type == LIBSSH2_EC_CURVE_NISTP256) {
        curve_name = "NID_X9_62_prime256v1";
        coordinate_len = 32;
    }
    else if(curve_type == LIBSSH2_EC_CURVE_NISTP384) {
        curve_name = "NID_secp384r1";
        coordinate_len = 48;
    }
    else if(curve_type == LIBSSH2_EC_CURVE_NISTP521) {
        curve_name = "NID_secp521r1";
        coordinate_len = 66;
    }
    else {
        return -1;
    }
    if(out == NULL || point == NULL || point_len != 1 + 2 * coordinate_len ||
       point[0] != 4 || private_scalar == NULL || private_scalar_len == 0) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    ctx->curve_type = curve_type;
    x = oh_view(point + 1, coordinate_len);
    y = oh_view(point + 1 + coordinate_len, coordinate_len);
    code = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC,
                                       &spec);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec(curve_name, &common);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetCommonParamsSpec(spec, common);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_ECC_PK_X_DATABLOB, &x);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_ECC_PK_Y_DATABLOB, &y);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_ECC_SK_DATABLOB, &sk);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(spec, &generator);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(generator,
                                                             &ctx->key_pair);
    }
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(generator);
    OH_CryptoAsymKeySpec_Destroy(common);
    OH_CryptoAsymKeySpec_Destroy(spec);
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_ed25519_components_keypair(_libssh2_ohcrypto_asym_ctx **out,
                                         const unsigned char *public_key,
                                         size_t public_key_len,
                                         const unsigned char *private_key,
                                         size_t private_key_len)
{
    _libssh2_ohcrypto_asym_ctx *ctx;
    oh_der_blob public_der;
    oh_der_blob private_der = {NULL, 0};
    Crypto_DataBlob public_blob;
    Crypto_DataBlob private_blob;
    static const unsigned char private_prefix[] = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };
    OH_Crypto_ErrCode code;
    if(out == NULL || public_key == NULL || private_key == NULL ||
       public_key_len != LIBSSH2_ED25519_KEY_LEN ||
       private_key_len != LIBSSH2_ED25519_KEY_LEN) {
        return -1;
    }
    *out = NULL;
    ctx = oh_asym_alloc();
    if(ctx == NULL) {
        return -1;
    }
    public_der = oh_rfc8410_public_der(0x70, public_key, public_key_len);
    private_der.length = sizeof(private_prefix) + private_key_len;
    private_der.data = (unsigned char *)malloc(private_der.length);
    if(public_der.data == NULL || private_der.data == NULL) {
        code = CRYPTO_MEMORY_ERROR;
    }
    else {
        memcpy(private_der.data, private_prefix, sizeof(private_prefix));
        memcpy(private_der.data + sizeof(private_prefix), private_key,
               private_key_len);
        public_blob = oh_view(public_der.data, public_der.length);
        private_blob = oh_view(private_der.data, private_der.length);
        code = OH_CryptoAsymKeyGenerator_Create("Ed25519", &ctx->generator);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Convert(ctx->generator, CRYPTO_DER,
                                                 &public_blob, &private_blob,
                                                 &ctx->key_pair);
    }
    if(private_der.data != NULL) {
        _libssh2_explicit_zero(private_der.data, private_der.length);
    }
    oh_der_free(&private_der);
    oh_der_free(&public_der);
    if(code != CRYPTO_SUCCESS) {
        _libssh2_ohcrypto_asym_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int oh_openssh_rsa_private(libssh2_rsa_ctx **ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *filedata, size_t filedata_length,
                                  const unsigned char *passphrase)
{
    struct string_buf *decrypted = NULL;
    unsigned char *type = NULL;
    unsigned char *n = NULL;
    unsigned char *e = NULL;
    unsigned char *d = NULL;
    size_t type_len = 0;
    size_t n_len = 0;
    size_t e_len = 0;
    size_t d_len = 0;
    int result = _libssh2_openssh_pem_parse_memory(session, passphrase,
        filedata, filedata_length, &decrypted);
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &type, &type_len);
    }
    if(result == 0 && (type_len != 7 || memcmp(type, "ssh-rsa", 7) != 0)) {
        result = -1;
    }
    if(result == 0) {
        result = _libssh2_get_bignum_bytes(decrypted, &n, &n_len);
    }
    if(result == 0) {
        result = _libssh2_get_bignum_bytes(decrypted, &e, &e_len);
    }
    if(result == 0) {
        result = _libssh2_get_bignum_bytes(decrypted, &d, &d_len);
    }
    if(result == 0) {
        result = oh_rsa_components_keypair(ctx, n, n_len, e, e_len, d, d_len);
    }
    if(decrypted != NULL) {
        _libssh2_string_buf_free(session, decrypted);
    }
    return result;
}

static int oh_openssh_ecdsa_private(libssh2_ecdsa_ctx **ctx,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata, size_t filedata_length,
                                    const unsigned char *passphrase)
{
    struct string_buf *decrypted = NULL;
    unsigned char *type = NULL;
    unsigned char *curve = NULL;
    unsigned char *point = NULL;
    unsigned char *scalar = NULL;
    size_t type_len = 0;
    size_t curve_len = 0;
    size_t point_len = 0;
    size_t scalar_len = 0;
    libssh2_curve_type curve_type;
    char type_name[20];
    int result = _libssh2_openssh_pem_parse_memory(session, passphrase,
        filedata, filedata_length, &decrypted);
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &type, &type_len);
    }
    if(result == 0 && type_len == 19) {
        memcpy(type_name, type, type_len);
        type_name[type_len] = 0;
        result = _libssh2_ecdsa_curve_type_from_name(type_name, &curve_type);
    }
    else if(result == 0) {
        result = -1;
    }
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &curve, &curve_len);
    }
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &point, &point_len);
    }
    if(result == 0) {
        result = _libssh2_get_bignum_bytes(decrypted, &scalar, &scalar_len);
    }
    if(result == 0) {
        result = oh_ecc_components_keypair(ctx, curve_type, point, point_len,
                                           scalar, scalar_len);
    }
    if(decrypted != NULL) {
        _libssh2_string_buf_free(session, decrypted);
    }
    (void)curve;
    (void)curve_len;
    return result;
}

static int oh_openssh_ed25519_private(libssh2_ed25519_ctx **ctx,
                                      LIBSSH2_SESSION *session,
                                      const char *filedata, size_t filedata_length,
                                      const unsigned char *passphrase)
{
    struct string_buf *decrypted = NULL;
    unsigned char *type = NULL;
    unsigned char *public_key = NULL;
    unsigned char *private_key = NULL;
    size_t type_len = 0;
    size_t public_len = 0;
    size_t private_len = 0;
    int result = _libssh2_openssh_pem_parse_memory(session, passphrase,
        filedata, filedata_length, &decrypted);
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &type, &type_len);
    }
    if(result == 0 && (type_len != 11 ||
       memcmp(type, "ssh-ed25519", 11) != 0)) {
        result = -1;
    }
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &public_key, &public_len);
    }
    if(result == 0) {
        result = _libssh2_get_string(decrypted, &private_key, &private_len);
    }
    if(result == 0 && public_len == LIBSSH2_ED25519_KEY_LEN &&
       private_len == LIBSSH2_ED25519_PRIVATE_KEY_LEN) {
        result = oh_ed25519_components_keypair(ctx, public_key, public_len,
                                               private_key,
                                               LIBSSH2_ED25519_KEY_LEN);
    }
    else if(result == 0) {
        result = -1;
    }
    if(decrypted != NULL) {
        _libssh2_string_buf_free(session, decrypted);
    }
    return result;
}

int _libssh2_ed25519_new_public(libssh2_ed25519_ctx **ctx,
                                LIBSSH2_SESSION *session,
                                const unsigned char *raw_public_key,
                                size_t key_length)
{
    oh_der_blob public_der;
    int result;
    (void)session;
    if(key_length != LIBSSH2_ED25519_KEY_LEN) {
        return -1;
    }
    public_der = oh_rfc8410_public_der(0x70, raw_public_key, key_length);
    result = oh_asym_import_public(ctx, "Ed25519", &public_der,
                                   LIBSSH2_EC_CURVE_NISTP256);
    oh_der_free(&public_der);
    return result;
}

int _libssh2_ed25519_verify(libssh2_ed25519_ctx *ctx,
                            const uint8_t *signature,
                            size_t signature_length,
                            const uint8_t *message, size_t message_length)
{
    OH_CryptoVerify *verify = NULL;
    Crypto_DataBlob message_blob;
    Crypto_DataBlob signature_blob;
    OH_Crypto_ErrCode code;
    bool verified = false;
    if(ctx == NULL || ctx->key_pair == NULL) {
        return -1;
    }
    message_blob = oh_view(message, message_length);
    signature_blob = oh_view(signature, signature_length);
    code = OH_CryptoVerify_Create("Ed25519", &verify);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(ctx->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        verified = OH_CryptoVerify_Final(verify, &message_blob, &signature_blob);
    }
    OH_CryptoVerify_Destroy(verify);
    return code == CRYPTO_SUCCESS && verified ? 0 : -1;
}

int _libssh2_ed25519_sign(libssh2_ed25519_ctx *ctx,
                          LIBSSH2_SESSION *session,
                          uint8_t **out_signature, size_t *out_signature_length,
                          const uint8_t *message, size_t message_length)
{
    OH_CryptoSign *sign = NULL;
    Crypto_DataBlob message_blob;
    Crypto_DataBlob output = {NULL, 0};
    OH_Crypto_ErrCode code;
    unsigned char *copy = NULL;
    if(ctx == NULL || ctx->key_pair == NULL || session == NULL ||
       out_signature == NULL || out_signature_length == NULL) {
        return -1;
    }
    message_blob = oh_view(message, message_length);
    code = OH_CryptoSign_Create("Ed25519", &sign);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(ctx->key_pair));
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Final(sign, &message_blob, &output);
    }
    if(code == CRYPTO_SUCCESS && output.len == LIBSSH2_ED25519_SIG_LEN) {
        copy = (unsigned char *)LIBSSH2_ALLOC(session, output.len);
        if(copy == NULL) {
            code = CRYPTO_MEMORY_ERROR;
        }
        else {
            memcpy(copy, output.data, output.len);
        }
    }
    else if(code == CRYPTO_SUCCESS) {
        code = CRYPTO_OPERTION_ERROR;
    }
    if(code == CRYPTO_SUCCESS) {
        *out_signature = copy;
        *out_signature_length = output.len;
    }
    else if(copy != NULL) {
        LIBSSH2_FREE(session, copy);
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoSign_Destroy(sign);
    return code == CRYPTO_SUCCESS ? 0 : -1;
}

static int oh_extract_rfc8410_private(const unsigned char *data,
                                      size_t data_length,
                                      const unsigned char **raw_private)
{
    size_t index;
    if(data == NULL || raw_private == NULL || data_length < 34) {
        return -1;
    }
    for(index = data_length - 34; index + 34 <= data_length; ++index) {
        if(data[index] == 0x04 && data[index + 1] == 0x20) {
            *raw_private = data + index + 2;
            return 0;
        }
        if(index + 34 == data_length) {
            break;
        }
    }
    return -1;
}

int _libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx **ctx,
                                             LIBSSH2_SESSION *session,
                                             const char *filedata,
                                             size_t filedata_length,
                                             const unsigned char *passphrase)
{
    const unsigned char *raw_private = NULL;
    int result;
    (void)session;
    result = oh_asym_import(ctx, "Ed25519", (const unsigned char *)filedata,
                            filedata_length, passphrase);
    if(result == 0) {
        return 0;
    }
    if(filedata_length >= 35 &&
       memcmp(filedata, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
        return oh_openssh_ed25519_private(ctx, session, filedata,
                                          filedata_length, passphrase);
    }
    if(passphrase != NULL && passphrase[0] != 0) {
        return -1;
    }
    if(oh_extract_rfc8410_private((const unsigned char *)filedata,
                                  filedata_length, &raw_private) != 0) {
        return -1;
    }
    return oh_raw_keypair(ctx, "Ed25519", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC,
                          CRYPTO_ED25519_SK_DATABLOB, raw_private,
                          LIBSSH2_ED25519_KEY_LEN);
}

int _libssh2_ed25519_new_private(libssh2_ed25519_ctx **ctx,
                                 LIBSSH2_SESSION *session,
                                 const char *filename,
                                 const unsigned char *passphrase)
{
    unsigned char *data = NULL;
    size_t length = 0;
    int result;
    if(oh_read_file(session, filename, &data, &length) != 0) {
        return -1;
    }
    result = _libssh2_ed25519_new_private_frommemory(ctx, session,
                                                     (const char *)data,
                                                     length, passphrase);
    _libssh2_explicit_zero(data, length);
    LIBSSH2_FREE(session, data);
    return result;
}

int _libssh2_ed25519_new_private_sk(libssh2_ed25519_ctx **ctx,
                                    unsigned char *flags,
                                    const char **application,
                                    const unsigned char **key_handle,
                                    size_t *handle_length,
                                    LIBSSH2_SESSION *session,
                                    const char *filename,
                                    const uint8_t *passphrase)
{
    (void)ctx; (void)flags; (void)application; (void)key_handle;
    (void)handle_length; (void)session; (void)filename; (void)passphrase;
    return -1;
}

int _libssh2_ed25519_new_private_frommemory_sk(libssh2_ed25519_ctx **ctx,
                                               unsigned char *flags,
                                               const char **application,
                                               const unsigned char **key_handle,
                                               size_t *handle_length,
                                               LIBSSH2_SESSION *session,
                                               const char *filedata,
                                               size_t filedata_length,
                                               const unsigned char *passphrase)
{
    (void)ctx; (void)flags; (void)application; (void)key_handle;
    (void)handle_length; (void)session; (void)filedata; (void)filedata_length;
    (void)passphrase;
    return -1;
}

int _libssh2_curve25519_new(LIBSSH2_SESSION *session,
                            uint8_t **out_public_key,
                            uint8_t **out_private_key)
{
    OH_CryptoAsymKeyGenerator *generator = NULL;
    OH_CryptoKeyPair *key_pair = NULL;
    Crypto_DataBlob public_raw = {NULL, 0};
    Crypto_DataBlob private_raw = {NULL, 0};
    unsigned char *public_copy = NULL;
    unsigned char *private_copy = NULL;
    OH_Crypto_ErrCode code;
    size_t index;
    if(session == NULL || out_public_key == NULL || out_private_key == NULL) {
        return -1;
    }
    code = OH_CryptoAsymKeyGenerator_Create("X25519", &generator);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(generator, &key_pair);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(key_pair),
                                        CRYPTO_X25519_PK_DATABLOB, &public_raw);
    }
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoPrivKey_GetParam(OH_CryptoKeyPair_GetPrivKey(key_pair),
                                         CRYPTO_X25519_SK_DATABLOB, &private_raw);
    }
    if(code == CRYPTO_SUCCESS &&
       (public_raw.len != LIBSSH2_ED25519_KEY_LEN ||
        private_raw.len != LIBSSH2_ED25519_KEY_LEN)) {
        code = CRYPTO_OPERTION_ERROR;
    }
    if(code == CRYPTO_SUCCESS) {
        public_copy = (unsigned char *)LIBSSH2_ALLOC(session, public_raw.len);
        private_copy = (unsigned char *)LIBSSH2_ALLOC(session, private_raw.len);
        if(public_copy == NULL || private_copy == NULL) {
            code = CRYPTO_MEMORY_ERROR;
        }
        else {
            /* CryptoFramework exposes X25519 key parameters in the reverse
             * byte order from the RFC 7748 strings used on the SSH wire. */
            for(index = 0; index < LIBSSH2_ED25519_KEY_LEN; index++) {
                public_copy[index] =
                    public_raw.data[LIBSSH2_ED25519_KEY_LEN - 1 - index];
                private_copy[index] =
                    private_raw.data[LIBSSH2_ED25519_KEY_LEN - 1 - index];
            }
        }
    }
    if(code == CRYPTO_SUCCESS) {
        *out_public_key = public_copy;
        *out_private_key = private_copy;
    }
    else {
        if(public_copy != NULL) {
            LIBSSH2_FREE(session, public_copy);
        }
        if(private_copy != NULL) {
            _libssh2_explicit_zero(private_copy, LIBSSH2_ED25519_KEY_LEN);
            LIBSSH2_FREE(session, private_copy);
        }
    }
    if(code != CRYPTO_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, OHCRYPTO_LOG_DOMAIN, OHCRYPTO_LOG_TAG,
                     "curve25519-new code=%{public}d pubLen=%{public}zu privLen=%{public}zu",
                     (int)code, public_raw.len, private_raw.len);
    }
    oh_data_blob_clear(&private_raw);
    OH_Crypto_FreeDataBlob(&public_raw);
    OH_CryptoKeyPair_Destroy(key_pair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
    return code == CRYPTO_SUCCESS ? 0 : -1;
}

int _libssh2_curve25519_gen_k(_libssh2_bn **secret,
                              uint8_t private_key[LIBSSH2_ED25519_KEY_LEN],
                              uint8_t server_public_key[LIBSSH2_ED25519_KEY_LEN])
{
    _libssh2_ohcrypto_asym_ctx *private_ctx = NULL;
    _libssh2_ohcrypto_asym_ctx *peer_ctx = NULL;
    OH_CryptoKeyAgreement *agreement = NULL;
    Crypto_DataBlob shared = {NULL, 0};
    unsigned char framework_private[LIBSSH2_ED25519_KEY_LEN];
    unsigned char framework_public[LIBSSH2_ED25519_KEY_LEN];
    OH_Crypto_ErrCode code = CRYPTO_OPERTION_ERROR;
    int result = -1;
    size_t index;
    if(secret == NULL || *secret == NULL) {
        return -1;
    }
    for(index = 0; index < LIBSSH2_ED25519_KEY_LEN; index++) {
        framework_private[index] =
            private_key[LIBSSH2_ED25519_KEY_LEN - 1 - index];
        framework_public[index] =
            server_public_key[LIBSSH2_ED25519_KEY_LEN - 1 - index];
    }
    if(oh_raw_keypair(&private_ctx, "X25519", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC,
                      CRYPTO_X25519_SK_DATABLOB, framework_private,
                      LIBSSH2_ED25519_KEY_LEN) != 0 ||
       oh_raw_keypair(&peer_ctx, "X25519", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC,
                      CRYPTO_X25519_PK_DATABLOB, framework_public,
                      LIBSSH2_ED25519_KEY_LEN) != 0) {
        goto cleanup;
    }
    code = OH_CryptoKeyAgreement_Create("X25519", &agreement);
    if(code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement,
            OH_CryptoKeyPair_GetPrivKey(private_ctx->key_pair),
            OH_CryptoKeyPair_GetPubKey(peer_ctx->key_pair), &shared);
    }
    if(code == CRYPTO_SUCCESS &&
       _libssh2_ohcrypto_bn_from_bin(*secret, shared.len, shared.data) == 0) {
        result = 0;
    }
cleanup:
    if(result != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, OHCRYPTO_LOG_DOMAIN, OHCRYPTO_LOG_TAG,
                     "curve25519-secret code=%{public}d sharedLen=%{public}zu",
                     (int)code, shared.len);
    }
    oh_data_blob_clear(&shared);
    OH_CryptoKeyAgreement_Destroy(agreement);
    _libssh2_ohcrypto_asym_free(peer_ctx);
    _libssh2_ohcrypto_asym_free(private_ctx);
    _libssh2_explicit_zero(framework_private, sizeof(framework_private));
    return result;
}

static int oh_public_blob_rsa(LIBSSH2_SESSION *session,
                              unsigned char **method, size_t *method_len,
                              unsigned char **pubkeydata, size_t *pubkeydata_len,
                              const unsigned char *exponent, size_t exponent_len,
                              const unsigned char *modulus, size_t modulus_len)
{
    unsigned char *method_copy;
    unsigned char *key;
    unsigned char *cursor;
    size_t capacity;
    if(session == NULL || method == NULL || pubkeydata == NULL ||
       exponent == NULL || exponent_len == 0 || modulus == NULL || modulus_len == 0 ||
       exponent_len > UINT32_MAX - 1 || modulus_len > UINT32_MAX - 1) {
        return -1;
    }
    capacity = 4 + 7 + 4 + exponent_len + 1 + 4 + modulus_len + 1;
    method_copy = (unsigned char *)LIBSSH2_ALLOC(session, 7);
    key = (unsigned char *)LIBSSH2_ALLOC(session, capacity);
    if(method_copy == NULL || key == NULL) {
        if(method_copy != NULL) {
            LIBSSH2_FREE(session, method_copy);
        }
        if(key != NULL) {
            LIBSSH2_FREE(session, key);
        }
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate RSA public key");
    }
    memcpy(method_copy, "ssh-rsa", 7);
    cursor = key;
    _libssh2_store_str(&cursor, "ssh-rsa", 7);
    _libssh2_store_bignum2_bytes(&cursor, exponent, exponent_len);
    _libssh2_store_bignum2_bytes(&cursor, modulus, modulus_len);
    *method = method_copy;
    *pubkeydata = key;
    if(method_len != NULL) {
        *method_len = 7;
    }
    if(pubkeydata_len != NULL) {
        *pubkeydata_len = (size_t)(cursor - key);
    }
    return 0;
}

static const char *oh_curve_method(libssh2_curve_type type)
{
    switch(type) {
        case LIBSSH2_EC_CURVE_NISTP256: return "ecdsa-sha2-nistp256";
        case LIBSSH2_EC_CURVE_NISTP384: return "ecdsa-sha2-nistp384";
        case LIBSSH2_EC_CURVE_NISTP521: return "ecdsa-sha2-nistp521";
        default: return NULL;
    }
}

static int oh_public_blob_ecdsa(LIBSSH2_SESSION *session,
                                unsigned char **method, size_t *method_len,
                                unsigned char **pubkeydata, size_t *pubkeydata_len,
                                libssh2_curve_type type,
                                const unsigned char *point, size_t point_len)
{
    const char *method_name = oh_curve_method(type);
    const char *curve_name;
    unsigned char *method_copy;
    unsigned char *key;
    unsigned char *cursor;
    size_t method_length;
    size_t curve_length;
    size_t key_length;
    if(session == NULL || method == NULL || pubkeydata == NULL ||
       method_name == NULL || point == NULL || point_len == 0 || point_len > UINT32_MAX) {
        return -1;
    }
    method_length = strlen(method_name);
    curve_name = method_name + 11;
    curve_length = method_length - 11;
    key_length = 4 + method_length + 4 + curve_length + 4 + point_len;
    method_copy = (unsigned char *)LIBSSH2_ALLOC(session, method_length);
    key = (unsigned char *)LIBSSH2_ALLOC(session, key_length);
    if(method_copy == NULL || key == NULL) {
        if(method_copy != NULL) {
            LIBSSH2_FREE(session, method_copy);
        }
        if(key != NULL) {
            LIBSSH2_FREE(session, key);
        }
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate ECDSA public key");
    }
    memcpy(method_copy, method_name, method_length);
    cursor = key;
    _libssh2_store_str(&cursor, method_name, method_length);
    _libssh2_store_str(&cursor, curve_name, curve_length);
    _libssh2_store_str(&cursor, (const char *)point, point_len);
    *method = method_copy;
    *pubkeydata = key;
    if(method_len != NULL) {
        *method_len = method_length;
    }
    if(pubkeydata_len != NULL) {
        *pubkeydata_len = key_length;
    }
    return 0;
}

static int oh_public_blob_ed25519(LIBSSH2_SESSION *session,
                                  unsigned char **method, size_t *method_len,
                                  unsigned char **pubkeydata, size_t *pubkeydata_len,
                                  const unsigned char *public_key, size_t public_key_len)
{
    unsigned char *method_copy;
    unsigned char *key;
    unsigned char *cursor;
    size_t key_length = 4 + 11 + 4 + LIBSSH2_ED25519_KEY_LEN;
    if(session == NULL || method == NULL || pubkeydata == NULL || public_key == NULL ||
       public_key_len != LIBSSH2_ED25519_KEY_LEN) {
        return -1;
    }
    method_copy = (unsigned char *)LIBSSH2_ALLOC(session, 11);
    key = (unsigned char *)LIBSSH2_ALLOC(session, key_length);
    if(method_copy == NULL || key == NULL) {
        if(method_copy != NULL) {
            LIBSSH2_FREE(session, method_copy);
        }
        if(key != NULL) {
            LIBSSH2_FREE(session, key);
        }
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate Ed25519 public key");
    }
    memcpy(method_copy, "ssh-ed25519", 11);
    cursor = key;
    _libssh2_store_str(&cursor, "ssh-ed25519", 11);
    _libssh2_store_str(&cursor, (const char *)public_key, public_key_len);
    *method = method_copy;
    *pubkeydata = key;
    if(method_len != NULL) {
        *method_len = 11;
    }
    if(pubkeydata_len != NULL) {
        *pubkeydata_len = key_length;
    }
    return 0;
}

static int oh_openssh_public_key(LIBSSH2_SESSION *session,
                                 unsigned char **method, size_t *method_len,
                                 unsigned char **pubkeydata, size_t *pubkeydata_len,
                                 const char *privatekeydata, size_t privatekeydata_len,
                                 const char *passphrase)
{
    struct string_buf *decrypted = NULL;
    unsigned char *type = NULL;
    size_t type_len = 0;
    int result;
    result = _libssh2_openssh_pem_parse_memory(session,
        (const unsigned char *)passphrase, privatekeydata, privatekeydata_len,
        &decrypted);
    if(result != 0) {
        return result;
    }
    result = _libssh2_get_string(decrypted, &type, &type_len);
    if(result == 0 && type_len == 7 && memcmp(type, "ssh-rsa", 7) == 0) {
        unsigned char *modulus = NULL;
        unsigned char *exponent = NULL;
        size_t modulus_len = 0;
        size_t exponent_len = 0;
        result = _libssh2_get_bignum_bytes(decrypted, &modulus, &modulus_len);
        if(result == 0) {
            result = _libssh2_get_bignum_bytes(decrypted, &exponent, &exponent_len);
        }
        if(result == 0) {
            result = oh_public_blob_rsa(session, method, method_len, pubkeydata,
                                        pubkeydata_len, exponent, exponent_len,
                                        modulus, modulus_len);
        }
    }
    else if(result == 0 && type_len == 11 &&
            memcmp(type, "ssh-ed25519", 11) == 0) {
        unsigned char *public_key = NULL;
        size_t public_key_len = 0;
        result = _libssh2_get_string(decrypted, &public_key, &public_key_len);
        if(result == 0) {
            result = oh_public_blob_ed25519(session, method, method_len,
                                            pubkeydata, pubkeydata_len,
                                            public_key, public_key_len);
        }
    }
    else if(result == 0 && type_len == 19 &&
            memcmp(type, "ecdsa-sha2-nistp", 17) == 0) {
        unsigned char *curve = NULL;
        unsigned char *point = NULL;
        size_t curve_len = 0;
        size_t point_len = 0;
        libssh2_curve_type curve_type;
        char type_name[20];
        memcpy(type_name, type, type_len);
        type_name[type_len] = 0;
        result = _libssh2_ecdsa_curve_type_from_name(type_name, &curve_type);
        if(result == 0) {
            result = _libssh2_get_string(decrypted, &curve, &curve_len);
        }
        if(result == 0) {
            result = _libssh2_get_string(decrypted, &point, &point_len);
        }
        if(result == 0) {
            result = oh_public_blob_ecdsa(session, method, method_len,
                                          pubkeydata, pubkeydata_len,
                                          curve_type, point, point_len);
        }
        (void)curve;
        (void)curve_len;
    }
    else {
        result = _libssh2_error(session, LIBSSH2_ERROR_FILE,
                                "Unsupported OpenSSH private key type");
    }
    _libssh2_string_buf_free(session, decrypted);
    return result;
}

static int oh_converted_public_key(LIBSSH2_SESSION *session,
                                   unsigned char **method, size_t *method_len,
                                   unsigned char **pubkeydata, size_t *pubkeydata_len,
                                   const char *privatekeydata, size_t privatekeydata_len,
                                   const char *passphrase)
{
    static const char *algorithms[] = {
        "RSA2048", "ECC256", "ECC384", "ECC521", "Ed25519"
    };
    size_t index;
    for(index = 0; index < sizeof(algorithms) / sizeof(algorithms[0]); index++) {
        _libssh2_ohcrypto_asym_ctx *ctx = NULL;
        if(oh_asym_import(&ctx, algorithms[index],
                          (const unsigned char *)privatekeydata,
                          privatekeydata_len,
                          (const unsigned char *)passphrase) == 0) {
            OH_CryptoPubKey *public_key = OH_CryptoKeyPair_GetPubKey(ctx->key_pair);
            Crypto_DataBlob first = {NULL, 0};
            Crypto_DataBlob second = {NULL, 0};
            int result = -1;
            if(index == 0) {
                OH_Crypto_ErrCode code = OH_CryptoPubKey_GetParam(
                    public_key, CRYPTO_RSA_E_DATABLOB, &first);
                if(code == CRYPTO_SUCCESS) {
                    code = OH_CryptoPubKey_GetParam(public_key,
                                                    CRYPTO_RSA_N_DATABLOB,
                                                    &second);
                }
                if(code == CRYPTO_SUCCESS) {
                    result = oh_public_blob_rsa(session, method, method_len,
                                                pubkeydata, pubkeydata_len,
                                                first.data, first.len,
                                                second.data, second.len);
                }
            }
            else if(index >= 1 && index <= 3) {
                libssh2_curve_type curve_type = index == 1 ?
                    LIBSSH2_EC_CURVE_NISTP256 : (index == 2 ?
                    LIBSSH2_EC_CURVE_NISTP384 : LIBSSH2_EC_CURVE_NISTP521);
                size_t coordinate_len = curve_type == LIBSSH2_EC_CURVE_NISTP256 ?
                    32 : (curve_type == LIBSSH2_EC_CURVE_NISTP384 ? 48 : 66);
                OH_Crypto_ErrCode code = OH_CryptoPubKey_GetParam(
                    public_key, CRYPTO_ECC_PK_X_DATABLOB, &first);
                if(code == CRYPTO_SUCCESS) {
                    code = OH_CryptoPubKey_GetParam(public_key,
                                                    CRYPTO_ECC_PK_Y_DATABLOB,
                                                    &second);
                }
                if(code == CRYPTO_SUCCESS && first.len <= coordinate_len &&
                   second.len <= coordinate_len) {
                    unsigned char point[1 + 2 * 66];
                    memset(point, 0, sizeof(point));
                    point[0] = 4;
                    memcpy(point + 1 + coordinate_len - first.len,
                           first.data, first.len);
                    memcpy(point + 1 + 2 * coordinate_len - second.len,
                           second.data, second.len);
                    result = oh_public_blob_ecdsa(session, method, method_len,
                        pubkeydata, pubkeydata_len, curve_type, point,
                        1 + 2 * coordinate_len);
                }
            }
            else {
                OH_Crypto_ErrCode code = OH_CryptoPubKey_GetParam(
                    public_key, CRYPTO_ED25519_PK_DATABLOB, &first);
                if(code == CRYPTO_SUCCESS) {
                    result = oh_public_blob_ed25519(session, method, method_len,
                                                   pubkeydata, pubkeydata_len,
                                                   first.data, first.len);
                }
            }
            OH_Crypto_FreeDataBlob(&second);
            OH_Crypto_FreeDataBlob(&first);
            _libssh2_ohcrypto_asym_free(ctx);
            if(result == 0) {
                return 0;
            }
        }
    }
    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                          "Unsupported private key format");
}

int _libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                    unsigned char **method,
                                    size_t *method_len,
                                    unsigned char **pubkeydata,
                                    size_t *pubkeydata_len,
                                    const char *privatekeydata,
                                    size_t privatekeydata_len,
                                    const char *passphrase)
{
    if(session == NULL || method == NULL || pubkeydata == NULL ||
       privatekeydata == NULL || privatekeydata_len == 0) {
        return -1;
    }
    if(privatekeydata_len >= 35 &&
       memcmp(privatekeydata, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
        return oh_openssh_public_key(session, method, method_len, pubkeydata,
                                     pubkeydata_len, privatekeydata,
                                     privatekeydata_len, passphrase);
    }
    return oh_converted_public_key(session, method, method_len, pubkeydata,
                                   pubkeydata_len, privatekeydata,
                                   privatekeydata_len, passphrase);
}

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              const char *privatekey,
                              const char *passphrase)
{
    unsigned char *data = NULL;
    size_t length = 0;
    int result;
    if(oh_read_file(session, privatekey, &data, &length) != 0) {
        return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                              "Unable to read private key file");
    }
    result = _libssh2_pub_priv_keyfilememory(session, method, method_len,
                                             pubkeydata, pubkeydata_len,
                                             (const char *)data, length,
                                             passphrase);
    _libssh2_explicit_zero(data, length);
    LIBSSH2_FREE(session, data);
    return result;
}

int _libssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session,
                                  unsigned char **method,
                                  size_t *method_len,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  int *algorithm,
                                  unsigned char *flags,
                                  const char **application,
                                  const unsigned char **key_handle,
                                  size_t *handle_len,
                                  const char *privatekeydata,
                                  size_t privatekeydata_len,
                                  const char *passphrase)
{
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                          "Security-key private keys are disabled");
}

const char *_libssh2_supported_key_sign_algorithms(
    LIBSSH2_SESSION *session, unsigned char *key_method,
    size_t key_method_len)
{
    if(key_method != NULL && key_method_len == 7 &&
       memcmp(key_method, "ssh-rsa", 7) == 0) {
        return oh_allows_rsa_sha1(session) ?
            "rsa-sha2-512,rsa-sha2-256,ssh-rsa" : "rsa-sha2-512,rsa-sha2-256";
    }
    return NULL;
}

/* DH 公共值必须位于 (1, p-1)，拒绝退化共享密钥和非法生成元。 */
static int oh_dh_valid_value(const _libssh2_bn *value, const _libssh2_bn *prime)
{
    size_t i;
    unsigned int borrow = 1;
    int differs = 0;
    if(value == NULL || prime == NULL || value->data == NULL || prime->data == NULL ||
       value->length == 0 || value->length > prime->length ||
       (value->length == 1 && value->data[0] <= 1))
        return 0;
    if(value->length < prime->length)
        return 1;
    if(memcmp(value->data, prime->data, prime->length) >= 0)
        return 0;
    for(i = prime->length; i > 0; --i) {
        unsigned int byte = prime->data[i - 1];
        unsigned int limit = (byte - borrow) & 0xff;
        borrow = borrow && byte == 0;
        differs |= value->data[i - 1] != limit;
    }
    return differs;
}

/* DH 上下文独占参数规格和密钥对；重试与释放均可重复调用。 */
void _libssh2_ohcrypto_dh_init(_libssh2_dh_ctx *ctx)
{
    if(ctx != NULL)
        memset(ctx, 0, sizeof(*ctx));
}

/* 使用 SSH 实际提供的 p/g，而不是根据位数猜测某个命名组。 */
int _libssh2_ohcrypto_dh_key_pair(_libssh2_dh_ctx *ctx, _libssh2_bn *public_key,
                                  const _libssh2_bn *generator,
                                  const _libssh2_bn *prime, int group_order)
{
    OH_CryptoAsymKeyGeneratorWithSpec *keygen = NULL;
    Crypto_DataBlob value = {NULL, 0};
    OH_Crypto_ErrCode code;
    size_t bits = _libssh2_ohcrypto_bn_bits(prime);
    int private_bits;
    unsigned char private_bits_bytes[4];
    if(ctx == NULL || public_key == NULL || prime == NULL ||
       bits < 1024 || bits > LIBSSH2_DH_MAX_MODULUS_BITS ||
       !(prime->data[prime->length - 1] & 1) || !oh_dh_valid_value(generator, prime) ||
       group_order <= 0 || group_order > INT_MAX / 8)
        return -1;
    private_bits = group_order * 8 - 1;
    if(private_bits >= (int)bits)
        private_bits = (int)bits - 1;
    /* CryptoFramework 的整数规格也使用网络字节序，不能传入本机 int 内存。 */
    _libssh2_htonu32(private_bits_bytes, (uint32_t)private_bits);
    _libssh2_ohcrypto_dh_dtor(ctx);
    code = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &ctx->params);
    Crypto_DataBlob p_blob = oh_view(prime->data, prime->length);
    Crypto_DataBlob g_blob = oh_view(generator->data, generator->length);
    Crypto_DataBlob l_blob = oh_view(private_bits_bytes, sizeof(private_bits_bytes));
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoAsymKeySpec_SetParam(ctx->params, CRYPTO_DH_P_DATABLOB, &p_blob);
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoAsymKeySpec_SetParam(ctx->params, CRYPTO_DH_G_DATABLOB, &g_blob);
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoAsymKeySpec_SetParam(ctx->params, CRYPTO_DH_L_INT, &l_blob);
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(ctx->params, &keygen);
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(keygen, &ctx->key_pair);
    if(code == CRYPTO_SUCCESS)
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(ctx->key_pair),
                                        CRYPTO_DH_PK_DATABLOB, &value);
    if(code == CRYPTO_SUCCESS &&
       (_libssh2_ohcrypto_bn_from_bin(public_key, value.len, value.data) != 0 ||
        _libssh2_ohcrypto_bn_from_bin(&ctx->prime, prime->length, prime->data) != 0 ||
        !oh_dh_valid_value(public_key, prime)))
        code = CRYPTO_OPERTION_ERROR;
    OH_Crypto_FreeDataBlob(&value);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(keygen);
    if(code != CRYPTO_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, OHCRYPTO_LOG_DOMAIN, OHCRYPTO_LOG_TAG,
                     "dh-key-pair code=%{public}d bits=%{public}zu", (int)code, bits);
        _libssh2_ohcrypto_dh_dtor(ctx);
        return -1;
    }
    return 0;
}

/* 对端公钥使用相同参数规格导入；引擎名只选择 DH 运算类型，参数来自密钥本身。 */
int _libssh2_ohcrypto_dh_secret(_libssh2_dh_ctx *ctx, _libssh2_bn *secret,
                                const _libssh2_bn *peer_public,
                                const _libssh2_bn *prime)
{
    OH_CryptoAsymKeySpec *peer_spec = NULL;
    OH_CryptoAsymKeyGeneratorWithSpec *peer_gen = NULL;
    OH_CryptoKeyPair *peer_key = NULL;
    OH_CryptoKeyAgreement *agreement = NULL;
    Crypto_DataBlob shared = {NULL, 0};
    OH_Crypto_ErrCode code;
    int result = -1;
    const char *stage = "peer-spec";
    if(ctx == NULL || ctx->params == NULL || ctx->key_pair == NULL || secret == NULL ||
       prime == NULL || ctx->prime.length != prime->length ||
       memcmp(ctx->prime.data, prime->data, prime->length) != 0 ||
       !oh_dh_valid_value(peer_public, prime))
        return -1;
    code = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &peer_spec);
    Crypto_DataBlob public_blob = oh_view(peer_public->data, peer_public->length);
    if(code == CRYPTO_SUCCESS) {
        stage = "peer-common";
        code = OH_CryptoAsymKeySpec_SetCommonParamsSpec(peer_spec, ctx->params);
    }
    if(code == CRYPTO_SUCCESS) {
        stage = "peer-public";
        code = OH_CryptoAsymKeySpec_SetParam(peer_spec, CRYPTO_DH_PK_DATABLOB, &public_blob);
    }
    if(code == CRYPTO_SUCCESS) {
        stage = "peer-generator";
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(peer_spec, &peer_gen);
    }
    if(code == CRYPTO_SUCCESS) {
        stage = "peer-key";
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(peer_gen, &peer_key);
    }
    if(code == CRYPTO_SUCCESS) {
        stage = "agreement";
        code = OH_CryptoKeyAgreement_Create("DH_modp2048", &agreement);
    }
    if(code == CRYPTO_SUCCESS) {
        stage = "derive";
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement,
            OH_CryptoKeyPair_GetPrivKey(ctx->key_pair), OH_CryptoKeyPair_GetPubKey(peer_key), &shared);
    }
    if(code == CRYPTO_SUCCESS &&
       _libssh2_ohcrypto_bn_from_bin(secret, shared.len, shared.data) == 0 &&
       oh_dh_valid_value(secret, prime))
        result = 0;
    if(result != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, OHCRYPTO_LOG_DOMAIN, OHCRYPTO_LOG_TAG,
                     "dh-secret stage=%{public}s code=%{public}d bits=%{public}zu",
                     stage, (int)code, _libssh2_ohcrypto_bn_bits(prime));
        oh_bn_clear(secret);
    }
    oh_data_blob_clear(&shared);
    OH_CryptoKeyAgreement_Destroy(agreement);
    OH_CryptoKeyPair_Destroy(peer_key);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(peer_gen);
    OH_CryptoAsymKeySpec_Destroy(peer_spec);
    return result;
}

/* 私钥由系统对象释放，受控大整数缓冲在释放前清零。 */
void _libssh2_ohcrypto_dh_dtor(_libssh2_dh_ctx *ctx)
{
    if(ctx == NULL)
        return;
    OH_CryptoKeyPair_Destroy(ctx->key_pair);
    OH_CryptoAsymKeySpec_Destroy(ctx->params);
    oh_bn_clear(&ctx->prime);
    memset(ctx, 0, sizeof(*ctx));
}

#endif /* LIBSSH2_CRYPTO_C */
