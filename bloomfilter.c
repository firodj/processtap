/*
  Copyright notice
  ================
  
  Copyright (C) 2010
      Lorenzo  Martignoni <martignlo@gmail.com>
      Roberto  Paleari    <roberto.paleari@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  ProcessTap is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
*/

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>

#include "bloomfilter.h"

#define HASH_FUNC_NO 9

unsigned int djbhash(unsigned char *d, unsigned int n) {
  unsigned int i;
  unsigned int h = 5381;
  
  for(i = 0; i < n; i++) {
    h = ((h << 5) + h) + d[i];
  }
  
  h = h & 0x7FFFFFFF;

  return h;
}

unsigned int elfhash(unsigned char *key, unsigned int len) {
  unsigned int hash = 0, x = 0, i = 0;

  for (i = 0; i < len; key++, i++) {
    hash = (hash << 4) + (*key);
    if ((x = hash & 0xF0000000L) != 0) {
      hash ^= x >> 24;
      /* The ELF ABI says `h &= ~g', but this is equivalent in
	 this case and on some machines one insn instead of two.  */
      hash ^= x;
    }
  }

  return hash;
}

unsigned int torekhash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++) {
    hash *= 33;
    hash += key[i];
  }

  return hash;
}

unsigned int phonghash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++)
    hash = hash * 129 + (unsigned int)(key[i]) + 987654321L;

  return hash;
}


#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
unsigned int fnvhash(unsigned char *key, unsigned int len) {
  unsigned int hash = FNV_OFFSET_32, i;
  for(i = 0; i < len; i++) {
    hash = hash ^ (key[i]);      // xor next byte into the bottom of the hash
    hash = hash * FNV_PRIME_32;  // Multiply by prime number found to work well
  }
  return hash;
}

unsigned int krhash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++)
    hash += key[i];

  return hash;
}

unsigned int sdbmhash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++)
    hash = key[i] + (hash << 6) + (hash << 16) - hash;

  return hash;
}

unsigned int korzendorferhash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++) {
    hash += key[i];
  }

  return hash;

}

unsigned int xorhash(unsigned char *key, unsigned int len) {
  unsigned int i, hash = 0;

  for (i = 0; i < len; i++)
    hash = hash ^ key[i];

  return hash;
}

typedef unsigned int(*hashfunc_ptr)(unsigned char *, unsigned int);

hashfunc_ptr hashfuncs[HASH_FUNC_NO] = {
  djbhash,
  elfhash,
  fnvhash,
  phonghash,
  torekhash,
  sdbmhash,
  krhash,
  korzendorferhash,
  xorhash,
};

bloomfilter_t *bloomfilter_init(unsigned int m, unsigned char k) {
  bloomfilter_t *bf = NULL;

  assert(k < HASH_FUNC_NO && k > 0);
  assert(m % 8 == 0 && m > 0);

  bf = (bloomfilter_t *) calloc(sizeof(bloomfilter_t), 1);
  assert(bf);

  // Set the number of hash functions to use
  bf->k = k;

  bf->m = m;
  bf->buckets = (unsigned char *) calloc(sizeof(unsigned char), m / 8);

  return bf;
}

void bloomfilter_destroy(bloomfilter_t *bf) {
  if (bf) {
    free(bf->buckets);
    free(bf);
  }
}

void bloomfilter_clear(bloomfilter_t *bf) {
  bf->n = 0;
  memset(bf->buckets, 0, sizeof(unsigned char) * bf->m / 8);
}

void bloomfilter_fill(bloomfilter_t *bf) {
  bf->n = (unsigned int) -1;
  memset(bf->buckets, '\xff', sizeof(unsigned char) * bf->m / 8);
}

void bloomfilter_add(bloomfilter_t *bf, unsigned char *k, unsigned int n) {
  unsigned int map_offset, bit, bit_mask, hk, i;

  bf->n++;

  for (i = 0; i < bf->k; i++) {
    hk = hashfuncs[i](k, n);
    bit = hk % bf->m;
    map_offset = floor(bit / 8);
    bit_mask = 1 << (bit & 7);
    bf->buckets[map_offset] |= bit_mask;
  }

  return;
}

int bloomfilter_contain(bloomfilter_t *bf, unsigned char *k, unsigned int n) {
  unsigned int map_offset, bit, bit_mask, hk, i;

  // Fast test to see in the filter has been saturated
  if (bf->n == (unsigned int) -1) {
    return 1;
  }

  for (i = 0; i < bf->k; i++) {
    hk = hashfuncs[i](k, n);
    bit = hk % bf->m;
    map_offset = floor(bit / 8);
    bit_mask = 1 << (bit & 7);
    if (!(bf->buckets[map_offset] & bit_mask)) {
      return 0;
    }
  }

  return  1;
}

void bloomfilter_union(bloomfilter_t *bf1, bloomfilter_t *bf2) {
  unsigned int i;

  assert(bf1->m == bf2->m);
  assert(bf1->k == bf2->k);

  for (i = 0; i < bf1->m / 8; i++) {
    bf1->buckets[i] |= bf2->buckets[i];
  }
}

void bloomfilter_intersect(bloomfilter_t *bf1, bloomfilter_t *bf2) {
  unsigned int i;

  assert(bf1->m == bf2->m);
  assert(bf1->k == bf2->k);

  for (i = 0; i < bf1->m / 8; i++) {
    bf1->buckets[i] &= bf2->buckets[i];
  }
}

bloomfilter_t *bloomfilter_copy(bloomfilter_t *bf1) {
  bloomfilter_t *bf2;

  bf2 = bloomfilter_init(bf1->m, bf1->k);

  memcpy(bf2, bf1, sizeof(*bf1));
  memcpy(bf2->buckets, bf1->buckets, bf1->m / 8);

  return bf2;
}

char *bloomfilter_str(bloomfilter_t *bf) {
  char *bfstr;
  unsigned int i, j;
  char z;

  bfstr = (char *) calloc(sizeof(char), bf->m + 10);

  for (i = 0; i < bf->m / 8; i++) {
    for (j = 0; j < 8; j++) {
      if (bf->buckets[i] & 1 << j) {
	z = '1';
      } else {
	z = '0';
      }

      bfstr[j + i * 8] = z;
    }
  }

  return bfstr;
}

// (1-e^(-kn/m))^k
double bloomfilter_fp(bloomfilter_t *bf) {
  return pow((1 - pow(M_E, -((double)bf->k * bf->n / bf->m))), (double)bf->k);
}

int bloomfilter_size(bloomfilter_t *bf) {
  return bf->n;
}
