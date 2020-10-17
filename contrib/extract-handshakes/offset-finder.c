// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */


#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// good grief,
// just import the necessary structs, defines and typedefs from kernel and
// 
// works with
//  arch: amd64
//  linux kernel: 5.8.11
//  wireguard-linux-compat: https://git.zx2c4.com/wireguard-linux-compat@25320ac50e6ddd8b935282f22dfddb579d528429

#define u8 uint8_t

struct def {
	const char *name;
	unsigned long offset;
	unsigned long indirection_offset;
};

#define CURVE25519_KEY_SIZE 32
#define NOISE_PUBLIC_KEY_LEN CURVE25519_KEY_SIZE
#define CHACHA20POLY1305_KEY_SIZE 32
#define NOISE_SYMMETRIC_KEY_LEN CHACHA20POLY1305_KEY_SIZE

struct noise_static_identity {
  u8 static_public[NOISE_PUBLIC_KEY_LEN];
  u8 static_private[NOISE_PUBLIC_KEY_LEN];
};

enum index_hashtable_type {
  INDEX_HASHTABLE_HANDSHAKE = 1U << 0,
  INDEX_HASHTABLE_KEYPAIR = 1U << 1
};

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

typedef unsigned int __u32;
typedef uint64_t u64;
typedef __u32 __bitwise __le32;

typedef __le32	f2fs_hash_t;

struct hlist_node {
  struct hlist_node *next, **pprev;
};

struct index_hashtable_entry {
  struct wg_peer *peer;
  struct hlist_node index_hash;
  enum index_hashtable_type type;
  __le32 index;
};


enum noise_handshake_state {
  HANDSHAKE_ZEROED,
  HANDSHAKE_CREATED_INITIATION,
  HANDSHAKE_CONSUMED_INITIATION,
  HANDSHAKE_CREATED_RESPONSE,
  HANDSHAKE_CONSUMED_RESPONSE
};


struct noise_handshake {
  struct index_hashtable_entry entry;

  enum noise_handshake_state state;
  u64 last_initiation_consumption;

  struct noise_static_identity *static_identity;

  u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  u8 remote_static[NOISE_PUBLIC_KEY_LEN];
  u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
  u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

  u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
};


const struct def defs[] = {
	{ "LOCAL_STATIC_PRIVATE_KEY", offsetof(struct noise_static_identity, static_private), offsetof(struct noise_handshake, static_identity) },
	{ "LOCAL_EPHEMERAL_PRIVATE_KEY", offsetof(struct noise_handshake, ephemeral_private), -1 },
	{ "REMOTE_STATIC_PUBLIC_KEY", offsetof(struct noise_handshake, remote_static), -1 },
	{ "PRESHARED_KEY", offsetof(struct noise_handshake, preshared_key), -1 },
	{ NULL, 0, 0 }
};
int main(int argc, char *argv[])
{
	puts("declare -A OFFSETS=(");
	for (const struct def *def = defs; def->name; ++def) {
		printf("\t[%s]=%ld", def->name, def->offset);
		if (def->indirection_offset != -1)
			printf(",%ld", def->indirection_offset);
		putchar('\n');
	}
	puts(")");
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	puts("ENDIAN=big");
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	puts("ENDIAN=little");
#else
#error "Unsupported endianness"
#endif
	return 0;
}
