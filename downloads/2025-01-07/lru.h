#ifndef LRU_H
#define LRU_H

#include <string.h>
#include "uthash.h"

typedef struct {
    char Bytes[16];
} uint128_t;

#define MAX_CACHE_SIZE 3
struct CacheEntry {
    uint128_t key ;
    uint128_t value;
    UT_hash_handle hh;
};
extern struct CacheEntry *cache;

void add_to_cache(uint128_t *key, uint128_t *value);
uint128_t *find_in_cache(uint128_t *key);


#endif // LRU_H
