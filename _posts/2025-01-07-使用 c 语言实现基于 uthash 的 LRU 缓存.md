---
title: 使用 c 语言实现基于 uthash 的 LRU 缓存
date: 2025-01-07
categories: [language, c]
tags: [c]
description: 在本文中，我们将介绍如何使用 C 语言和 uthash 库来实现一个简单而高效的 LRU 缓存。
---

## LRU 算法简介

LRU (Least Recently Used) 缓存是一种常用的缓存淘汰算法，它的核心思想是"最近使用的数据应该被保留，而最久未使用的数据应该被淘汰"。

LRU 算法的工作原理如下：
1. 新数据插入到缓存中时，如果缓存已满，会优先淘汰最久未使用的数据
2. 当访问缓存中的某个数据时，该数据会被标记为最近使用，从而降低被淘汰的优先级
3. 缓存满时，会淘汰最久未被访问的数据

这种策略在实际应用中非常有效，因为它符合程序的局部性原理：最近被访问过的数据很可能在近期再次被访问。

## uthash 库简介

uthash 是一个用于 C 语言的哈希表实现库，它通过宏的方式提供了哈希表的各种操作。

Repo: https://github.com/troydhanson/uthash

Docs: https://troydhanson.github.io/uthash/userguide#_a_hash_in_c

使用 uthash 的主要优点包括：

1. 使用简单：通过宏定义实现，不需要复杂的数据结构操作
2. 性能优秀：底层实现高效
3. 只需要包含头文件：整个库都在一个头文件中实现
4. 支持任意类型的键：可以使用整数、字符串或自定义类型作为键

## 项目实现详解

> 本项目参考了https://jehiah.cz/a/uthash

### 数据结构设计

首先，我们定义了缓存条目的结构：

```c
typedef struct {
    char Bytes[16];
} uint128_t;

struct CacheEntry {
    uint128_t key;
    uint128_t value;
    UT_hash_handle hh;
};
```

注意事项：
- `UT_hash_handle hh` 是 uthash 必需的字段，用于维护哈希表
- 我们使用自定义的 `uint128_t` 类型来存储键值对

### 核心函数实现

#### 查找缓存项

```c
uint128_t *find_in_cache(uint128_t *key)
{
    struct CacheEntry *entry;
    HASH_FIND(hh, cache, key, sizeof(uint128_t), entry);
    if (entry) {	
        // 删除并重新添加，使其成为最新项
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, cache, entry);
        HASH_ADD(hh, cache, key, sizeof(uint128_t), entry);
        return &entry->value;
    }
    return NULL;
}
```

实现要点：
- 使用 `HASH_FIND` 查找缓存项
- 找到后，通过删除并重新添加的方式将其移动到链表头部
- 这样实现了**最近使用**的更新

#### 添加缓存项

```c
void add_to_cache(uint128_t *key, uint128_t *value)
{
    struct CacheEntry *entry, *tmp_entry;

    // prune the cache to MAX_CACHE_SIZE 如果缓存已满，删除最旧的项
    if (HASH_COUNT(cache) >= MAX_CACHE_SIZE) {
        HASH_ITER(hh, cache, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, cache, entry);
            free(entry);
            break;
        }
    }

    entry = malloc(sizeof(struct CacheEntry));
    if (entry == NULL) {
        // 分配内存错误
        return;
    }
    entry->key = *key;
    entry->value = *value;
    HASH_ADD(hh, cache, key, sizeof(uint128_t), entry);
}

```

实现要点：
- 使用 `HASH_COUNT` 检查缓存大小
- 通过 `HASH_ITER` 遍历缓存项，删除最旧的项
- 使用 `HASH_ADD` 添加新项到哈希表

### uthash 关键操作说明

在实现中，我们使用了以下 uthash 核心操作：

1. `HASH_FIND`：查找哈希表中的项
2. `HASH_ADD`：添加新项到哈希表
3. `HASH_DELETE`：从哈希表中删除项
4. `HASH_COUNT`：获取哈希表中的项数
5. `HASH_ITER`：遍历哈希表

`uthash` 的一个重要特性是它维护了插入顺序，这使得实现 LRU 变得简单：最早插入的项在遍历时会最先被访问到，这正好符合我们需要淘汰最旧项的需求。

## 测试结果分析

1. 基本的添加和查找操作
2. 处理不存在的键
3. 容量限制和 LRU 淘汰机制
4. 访问顺序更新

我们通过一系列测试用例来验证 LRU 缓存的功能。让我们详细分析每个测试用例：

### 测试1：基本的添加和查找操作

操作：
```c
add_to_cache(&key_a, &val_a);  // "key-a": "val-a"
add_to_cache(&key_b, &val_b);  // "key-b": "val-b"
add_to_cache(&key_c, &val_c);  // "key-c": "val-c"
printf("Test 1: Add and find items\n");
printf("%s: %s\n", key_a.Bytes, find_in_cache(&key_a)->Bytes);  // 应输出 val-a
printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 val-c
```

输出结果：
```
Test 1: Add and find items
key-a: val-a
key-b: val-b
key-c: val-c
```

这个测试验证了缓存的基本功能：可以正确添加和检索键值对。此时缓存达到最大容量（3项）。

### 测试2：查找不存在的键

操作：
```c
printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 查找不存在的 "key-d" 应输出 (null)
```

输出结果：
```
Test 2: Find non-existent item
key-d: (null)
```

这个测试验证了缓存对不存在项的处理：正确返回 null。

### 测试3：触发 LRU 淘汰机制

输入操作：
```c
add_to_cache(&key_d, &val_d); // 添加新项 "key-d": "val-d"，应淘汰 key-a
printf("%s: %s\n", key_a.Bytes, find_in_cache(&key_a)->Bytes);  // 应输出 (null)，因为 key-a 被淘汰
printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 val-c
printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 应输出 val-d
```

输出结果：
```
Test 3: Trigger LRU eviction
key-a: (null)        // key-a 被淘汰
key-b: val-b        // 保留
key-c: val-c        // 保留
key-d: val-d        // 新添加
```

这个测试展示了 LRU 淘汰机制：
- 当添加第 4 个项时，最久未使用的 key-a 被自动淘汰
- 缓存大小维持在 3 个项
- 其他项（key-b, key-c）保持不变
- 新项（key-d）成功添加

### 测试4：更新访问顺序

输入操作：
```c
printf("Access %s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 访问 key-b，将其移到最近使用
add_to_cache(&key_e, &val_e);  // 添加新项 "key-e": "val-e"，应淘汰 key-c
printf("%s: %s\n", key_b.Bytes, find_in_cache(&key_b)->Bytes);  // 应输出 val-b
printf("%s: %s\n", key_c.Bytes, find_in_cache(&key_c)->Bytes);  // 应输出 (null)，因为 key-c 被淘汰
printf("%s: %s\n", key_d.Bytes, find_in_cache(&key_d)->Bytes);  // 应输出 val-d
printf("%s: %s\n", key_e.Bytes, find_in_cache(&key_e)->Bytes);  // 应输出 val-e
```

输出结果：
```
Test 4: Update access order
Access key-b: val-b
key-b: val-b        // 因为刚被访问，所以保留
key-c: (null)       // 被淘汰
key-d: val-d        // 保留
key-e: val-e        // 新添加
```

这个测试验证了访问顺序更新机制：
- 访问 key-b 后，它被标记为最近使用
- 添加 key-e 时，key-c 被淘汰（而不是 key-b）
- 最终缓存中保留了：key-b（最近访问）、key-d 和 key-e（最新添加）

### 结果分析

这些测试结果清楚地展示了 LRU 缓存的核心特性：
1. 维持固定的缓存大小（3项）
2. 自动淘汰最久未使用的项
3. 访问项会更新其使用时间
4. 正确处理不存在的键查询

## 总结

通过使用 uthash 库，我们实现了一个简单而高效的 LRU 缓存。uthash 的哈希表实现和内置的插入顺序维护特性，使得 LRU 缓存的实现变得相对简单。这个实现可以作为更复杂缓存系统的基础，通过添加更多功能（如过期时间、容量动态调整等）来满足不同的需求。

## 源码

```bash
tree
.
├── CMakeLists.txt
├── lru.c
├── lru.h
├── main.c
└── uthash.h
```

[CMakeLists.txt](/downloads/2025-01-07/CMakeLists.txt)

[lru.c](/downloads/2025-01-07/lru.c)

[lru.h](/downloads/2025-01-07/lru.h)

[main.c](/downloads/2025-01-07/main.c)

[uthash.h](https://github.com/troydhanson/uthash/blob/master/src/uthash.h)