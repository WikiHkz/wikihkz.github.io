#include <stdio.h>
#include "lru.h"

int main() {
    uint128_t key_a, val_a;
    strcpy(key_a.Bytes, "key-a");
    strcpy(val_a.Bytes, "val-a");
    uint128_t key_b, val_b;
    strcpy(key_b.Bytes, "key-b");
    strcpy(val_b.Bytes, "val-b");
    uint128_t key_c, val_c;
    strcpy(key_c.Bytes, "key-c");
    strcpy(val_c.Bytes, "val-c");
    uint128_t key_d, val_d;
    strcpy(key_d.Bytes, "key-d");
    strcpy(val_d.Bytes, "val-d");
    uint128_t key_e, val_e;
    strcpy(key_e.Bytes, "key-e");
    strcpy(val_e.Bytes, "val-e");

    // // 测试 1: 添加和查找缓存项
    add_to_cache(&key_a, &val_a);
    add_to_cache(&key_b, &val_b);
    add_to_cache(&key_c, &val_c);


    printf("Test 1: Add and find items\n");
    printf("%s: %s\n", key_a.Bytes, find_in_cache(&key_a)->Bytes);  // 应输出 val-a
    printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
    printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 val-c
    printf("\n");

    // 测试 2: 查找不存在的缓存项
    printf("Test 2: Find non-existent item\n");
    printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 查找不存在的 "key-d" 应输出 (null)
    printf("\n");

    // 测试 3: 触发 LRU 淘汰
    printf("Test 3: Trigger LRU eviction\n");
    add_to_cache(&key_d, &val_d); // 添加新项 "key-d": "val-d"，应淘汰 key-a
    printf("%s: %s\n", key_a.Bytes, find_in_cache(&key_a)->Bytes);  // 应输出 (null)，因为 key-a 被淘汰
    printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
    printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 val-c
    printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 应输出 val-d
    printf("\n");

    // 测试 4: 更新缓存项的访问顺序
    printf("Test 4: Update access order\n");
    printf("Access %s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 访问 key-b，将其移到最近使用
    add_to_cache(&key_e, &val_e);  // 添加新项 "key-e": "val-e"，应淘汰 key-c
    printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
    printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 (null)，因为 key-c 被淘汰
    printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 应输出 val-d
    printf("%s: %s\n", key_e.Bytes, find_in_cache(&key_e)->Bytes);  // 应输出 val-e
    printf("\n");

    // 清理缓存
    struct CacheEntry *entry, *tmp_entry;
    HASH_ITER(hh, cache, entry, tmp_entry) {
        HASH_DELETE(hh, cache, entry);
        free(entry);
    }

    printf("All tests completed.\n");
    return 0;
}
