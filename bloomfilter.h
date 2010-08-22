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

#ifndef __BLOOM_FILTER__
#define __BLOOM_FILTER__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  unsigned char k;
  unsigned int m;
  unsigned char *buckets;
  unsigned int n;
} bloomfilter_t;

bloomfilter_t *bloomfilter_init(unsigned int m, unsigned char k);
void bloomfilter_destroy(bloomfilter_t *bf);
void bloomfilter_clear(bloomfilter_t *bf);
void bloomfilter_fill(bloomfilter_t *bf);

void bloomfilter_add(bloomfilter_t *, unsigned char *, unsigned int);
int bloomfilter_contain(bloomfilter_t *, unsigned char *, unsigned int);

void bloomfilter_union(bloomfilter_t *, bloomfilter_t *);
void bloomfilter_intersect(bloomfilter_t *, bloomfilter_t *);

bloomfilter_t *bloomfilter_copy(bloomfilter_t *);

double bloomfilter_fp(bloomfilter_t *bf);

int bloomfilter_size(bloomfilter_t *bf);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
