/*
 * @Author: su-cheng
 * @Description: 
 *    Simple hash table implemented in c by wrapperring around the function in "uthash.h"
 *    key type supported: void* 
 *    value type supproted: void*
 * @TODO：
 */

#ifndef _HT_H
#define _HT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"

typedef struct my_struct 
{
    void *key;
    void *value;
    UT_hash_handle hh;
} ht_item;

/*
 * OP Fuctions:
 * 1. insert an item into hash table.
 * 2. insert an item into hash table(allow overwriting).
 * 3. delete item with given key in the hash table.
 * 4. get item with given key from hash table.
 * 5. update item with given key.
 * 6. frees the entire hash table.
 * 7. gets the length of the hash table
 */
int insert_item(ht_item **ht_head, void *key, size_t key_size, void *value)
{
    ht_item *add;

    HASH_FIND(hh, *ht_head, key, key_size, add);
    if (add == NULL) 
    {
        add = (ht_item*)malloc(sizeof *add);
        add->key = key;
        add->value = value;
        HASH_ADD_KEYPTR(hh, *ht_head, key, key_size, add);
        return 1;
    } 
    else 
    {
        fprintf(stderr, "the key already exists in the hash table.\n");
        return 0;
    }
}

int insert_item_over(ht_item **ht_head, void *key, size_t key_size, void *value)
{
    ht_item *add;

    HASH_FIND(hh, *ht_head, key, key_size, add);
    if (add == NULL) 
    {
        add = (ht_item*)malloc(sizeof *add);
        add->key = key;
        HASH_ADD_KEYPTR(hh, *ht_head, key, key_size, add);
    }
    add->value = value;
    return 1;
}

int delete_item(ht_item **ht_head, void *key, size_t key_size)
{
    ht_item *del;

    HASH_FIND(hh, *ht_head, key, key_size, del);
    if (del == NULL) 
    {
        fprintf(stderr, "it does not exist in the table.\n");
        return 0;
    } 
    else 
    {
        HASH_DEL(*ht_head, del);
        free(del);
        return 1;
    }
}

ht_item *find_item(ht_item **ht_head, void *key, size_t key_size)
{
    ht_item *des;

    HASH_FIND(hh, *ht_head, key, key_size, des);
    return des;
}

int update_item(ht_item **ht_head, void *key, size_t key_size, void *value)
{
    ht_item *add, *replaced;

    HASH_FIND(hh, *ht_head, key, key_size, replaced);
    if (replaced == NULL) 
    {
        fprintf(stderr, "it does not exist in the table.\n");
        return 0;
    } 
    else 
    {   
        HASH_DEL(*ht_head, replaced);
        add = (ht_item*)malloc(sizeof *add);
        add->key = key;
        add->value = value;
        HASH_ADD_KEYPTR(hh, *ht_head, key, key_size, add);
        return 1;
    }
}

int delete_all(ht_item **ht_head)
{
    ht_item *current_user;
    ht_item *tmp;

    HASH_ITER(hh, *ht_head, current_user, tmp) {
        HASH_DEL(*ht_head, current_user);  /* delete it (users advances to next) */
        free(current_user);               /* free it */
    }
    return 1;
}

int length(ht_item *ht_head)
{
    return HASH_COUNT(ht_head);
}

#endif