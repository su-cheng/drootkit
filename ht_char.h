/*
 * @Author: su-cheng
 * @Description: 
 *    Simple hash table implemented in c.
 *    key type supported：char*
 *    value type supproted: void*
 * @TODO：
 */

#ifndef _HT_CHAR_H
#define _HT_CHAR_H

#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 140000 // must not be zero

typedef struct entry {
    const char *key;
    void *value;
} ht_entry;

typedef struct ht {
    ht_entry *entries; 
    size_t capacity;
    size_t length;
} ht_char;

/*
 * Create and destory a hash table:
 * 1. Create hash table with ht_create.
 * 2. Free the memory with ht_destroy.
 */
ht_char *ht_create(void);
void ht_destroy(ht_char *table);

/*
 * OP functions:
 * 1. Get item with given key (NUL-terminated) from hash table.
 * 2. Set item with given key (NUL-terminated) to value (which must not be NULL).
 * 3. Return number of items in hash table.
 */
void *ht_get(ht_char *table, const char *key);
const char *ht_set(ht_char *table, const char *key, void *value);
size_t ht_length(ht_char *table);

/*
 * Traverses the hash table.
 * 1. Create iterator with ht_iterator.
 * 2. Find the next item with ht_next.
 */
typedef struct {
    const char *key;
    void *value;

    // Don't use these fields directly.
    ht_char *_table;
    size_t _index;
} hti;
hti ht_iterator(ht_char *table);
bool ht_next(hti *it);

ht_char *ht_create(void) {
    ht_char *table = malloc(sizeof(ht_char));
    if (table == NULL) {
        return NULL;
    }
    table->length = 0;
    table->capacity = INITIAL_CAPACITY;

    table->entries = calloc(table->capacity, sizeof(ht_entry));
    if (table->entries == NULL) {
        free(table); // error, free table before we return!
        return NULL;
    }
    return table;
}

void ht_destroy(ht_char *table) {
    // First free allocated keys.
    for (size_t i = 0; i < table->capacity; i++) {
        free((void *)table->entries[i].key);
    }

    free(table->entries);
    free(table);
}

#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

/* 
 * Return 64-bit FNV-1a hash for key (NUL-terminated). 
 * See description: https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
 */
static uint64_t hash_key(const char *key) {
    uint64_t hash = FNV_OFFSET;
    for (const char *p = key; *p; p++) {
        hash ^= (uint64_t)(unsigned char)(*p);
        hash *= FNV_PRIME;
    }
    return hash;
}

void *ht_get(ht_char *table, const char *key) {
    // AND hash with capacity-1 to ensure it's within entries array.
    uint64_t hash = hash_key(key);
    size_t index = (size_t)(hash & (uint64_t)(table->capacity - 1));

    while (table->entries[index].key != NULL) {
        if (strcmp(key, table->entries[index].key) == 0) {
            return table->entries[index].value;
        }
        index++;
        if (index >= table->capacity) {
            index = 0;
        }
    }
    return NULL;
}

/* 
 * Internal function to set an entry (without expanding table).
 */
static const char *ht_set_entry(ht_entry *entries, size_t capacity, const char *key, void *value, size_t *plength) {
    uint64_t hash = hash_key(key);
    size_t index = (size_t)(hash & (uint64_t)(capacity - 1));

    while (entries[index].key != NULL) {
        if (strcmp(key, entries[index].key) == 0) {
            entries[index].value = value;
            return entries[index].key;
        }
        index++;
        if (index >= capacity) {
            index = 0;
        }
    }

    // Didn't find key, allocate+copy if needed, then insert it.
    if (plength != NULL) {
        key = strdup(key);
        if (key == NULL) {
            return NULL;
        }
        (*plength)++;
    }
    entries[index].key = (char *)key;
    entries[index].value = value;
    return key;
}

/*
 * Expand hash table to twice its current size. Return true on success,
 * false if out of memory.
 */
static bool ht_expand(ht_char *table) {
    size_t new_capacity = table->capacity * 2;
    if (new_capacity < table->capacity) {
        return false; // overflow (capacity would be too big)
    }

    ht_entry *new_entries = calloc(new_capacity, sizeof(ht_entry));
    if (new_entries == NULL) {
        return false;
    }

    // Iterate entries, move all non-empty ones to new table's entries.
    for (size_t i = 0; i < table->capacity; i++) {
        ht_entry entry = table->entries[i];
        if (entry.key != NULL) {
            ht_set_entry(new_entries, new_capacity, entry.key,
                         entry.value, NULL);
        }
    }

    // Free old entries array and update this table's details.
    free(table->entries);
    table->entries = new_entries;
    table->capacity = new_capacity;
    return true;
}

const char *ht_set(ht_char *table, const char *key, void *value) {
    assert(value != NULL);
    if (value == NULL) {
        return NULL;
    }

    // If length will exceed half of current capacity, expand it.
    if (table->length >= table->capacity / 2) {
        if (!ht_expand(table)) {
            return NULL;
        }
    }

    // Set entry and update length.
    return ht_set_entry(table->entries, table->capacity, key, value,
                        &table->length);
}

size_t ht_length(ht_char *table) {
    return table->length;
}

hti ht_iterator(ht_char *table) {
    hti it;
    it._table = table;
    it._index = 0;
    return it;
}

bool ht_next(hti *it) {
    ht_char *table = it->_table;
    while (it->_index < table->capacity) {
        size_t i = it->_index;
        it->_index++;
        if (table->entries[i].key != NULL) {
            ht_entry entry = table->entries[i];
            it->key = entry.key;
            it->value = entry.value;
            return true;
        }
    }
    return false;
}

#endif