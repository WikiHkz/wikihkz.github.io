#include "lru.h"

struct CacheEntry *cache = NULL;

uint128_t *find_in_cache(uint128_t *key)
{
    struct CacheEntry *entry;
    HASH_FIND(hh, cache, key, sizeof(uint128_t), entry);
    if (entry)
    {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, cache, entry);
        HASH_ADD(hh, cache, key, sizeof(uint128_t), entry);
        return &entry->value;
    }
    return NULL;
}

void add_to_cache(uint128_t *key, uint128_t *value)
{
    struct CacheEntry *entry, *tmp_entry;

    // prune the cache to MAX_CACHE_SIZE
    if (HASH_COUNT(cache) >= MAX_CACHE_SIZE)
    {
        HASH_ITER(hh, cache, entry, tmp_entry)
        {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, cache, entry);
            free(entry);
            break;
        }
    }

    entry = malloc(sizeof(struct CacheEntry));
    if (entry == NULL)
    {
        // 分配内存错误
        return;
    }
    entry->key = *key;
    entry->value = *value;
    HASH_ADD(hh, cache, key, sizeof(uint128_t), entry);
}
