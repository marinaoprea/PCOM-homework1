#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>
#include <arpa/inet.h>
#include "lib.h"

struct node {
    uint32_t data_len;
    struct node* children[2];
    int *data;
};

typedef struct node node_t;

node_t* create_node(void);

void insert_address(node_t *root, struct route_table_entry entry, int index);

int search(node_t *root, uint32_t address);

#endif