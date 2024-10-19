/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef HASH_SHAKE_H
#define HASH_SHAKE_H

#include <stdint.h>
#include <stdio.h>

#include "macros.h"
#include "endian_compat.h"
#include "KeccakHash.h"


typedef Keccak_HashInstance hash_context;

/**
 * Initialize hash context based on the security parameter. If the security parameter is 128,
 * SHAKE128 is used, otherwise SHAKE256 is used.
 */
static inline void hash_init(hash_context* ctx, unsigned int security_param) {
    Keccak_HashInitialize_SHAKE256(ctx);
}

static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {
  Keccak_HashUpdate(ctx, data, size << 3);
}

static inline void hash_final(hash_context* ctx) {
  Keccak_HashFinal(ctx, NULL);
}

static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {
  Keccak_HashSqueeze(ctx, buffer, buflen << 3);
}

#define hash_clear(ctx)
#endif

static inline void hash_update_uint16_le(hash_context* ctx, uint16_t data) {
  const uint16_t data_le = htole16(data);
  hash_update(ctx, (const uint8_t*)&data_le, sizeof(data_le));
}

static inline void hash_init_prefix(hash_context* ctx, unsigned int security_param,
                                    const uint8_t prefix) {
  hash_init(ctx, security_param);
  hash_update(ctx, &prefix, sizeof(prefix));
}

/* Instances that work with 4 states in parallel using the base Keccak implementation. */
typedef struct hash_context_x4_s {
  hash_context instances[4];
} hash_context_x4;

static inline void hash_init_x4(hash_context_x4* ctx, unsigned int security_param) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_init(&ctx->instances[i], security_param);
  }
}

static inline void hash_update_x4(hash_context_x4* ctx, const uint8_t** data, size_t size) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_update(&ctx->instances[i], data[i], size);
  }
}

static inline void hash_update_x4_4(hash_context_x4* ctx, const uint8_t* data0,
                                    const uint8_t* data1, const uint8_t* data2,
                                    const uint8_t* data3, size_t size) {
  hash_update(&ctx->instances[0], data0, size);
  hash_update(&ctx->instances[1], data1, size);
  hash_update(&ctx->instances[2], data2, size);
  hash_update(&ctx->instances[3], data3, size);
}

static inline void hash_update_x4_1(hash_context_x4* ctx, const uint8_t* data, size_t size) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_update(&ctx->instances[i], data, size);
  }
}

static inline void hash_init_prefix_x4(hash_context_x4* ctx, unsigned int security_param,
                                       const uint8_t prefix) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_init_prefix(&ctx->instances[i], security_param, prefix);
  }
}

static inline void hash_final_x4(hash_context_x4* ctx) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_final(&ctx->instances[i]);
  }
}

static inline void hash_squeeze_x4(hash_context_x4* ctx, uint8_t** buffer, size_t buflen) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_squeeze(&ctx->instances[i], buffer[i], buflen);
  }
}

static inline void hash_squeeze_x4_4(hash_context_x4* ctx, uint8_t* buffer0, uint8_t* buffer1,
                                     uint8_t* buffer2, uint8_t* buffer3, size_t buflen) {
  hash_squeeze(&ctx->instances[0], buffer0, buflen);
  hash_squeeze(&ctx->instances[1], buffer1, buflen);
  hash_squeeze(&ctx->instances[2], buffer2, buflen);
  hash_squeeze(&ctx->instances[3], buffer3, buflen);
}

#define hash_clear_x4(ctx)

static inline void hash_update_x4_uint16_le(hash_context_x4* ctx, uint16_t data) {
  const uint16_t data_le = htole16(data);
  hash_update_x4_1(ctx, (const uint8_t*)&data_le, sizeof(data_le));
}

static inline void hash_update_x4_uint16s_le(hash_context_x4* ctx, const uint16_t data[4]) {
  const uint16_t data0_le = htole16(data[0]);
  const uint16_t data1_le = htole16(data[1]);
  const uint16_t data2_le = htole16(data[2]);
  const uint16_t data3_le = htole16(data[3]);
  hash_update_x4_4(ctx, (const uint8_t*)&data0_le, (const uint8_t*)&data1_le,
                   (const uint8_t*)&data2_le, (const uint8_t*)&data3_le, sizeof(data[0]));
}

