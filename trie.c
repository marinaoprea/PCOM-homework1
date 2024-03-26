#include "trie.h"
#include <stdlib.h>

node_t* create_node(void)
{
    node_t* node = malloc(sizeof(node_t));
    node->data_len = 0;
    node->data = NULL;
    node->children[0] = NULL;
    node->children[1] = NULL;
    return node;
}

void insert_address(node_t *root, struct route_table_entry entry, int index)
{
    node_t *curr = root;
    for (int i = 31; (ntohl(entry.mask) & (1 << i)) && i; i--) {
        uint8_t bit = (ntohl(entry.prefix) & (1 << i)) >> i;
        if (!curr->children[bit]) {
            curr->children[bit] = create_node();
        }
        curr = curr->children[bit];
    }

    curr->data_len++;
    uint32_t new_len = curr->data_len;
    curr->data = realloc(curr->data, new_len * sizeof(int));
    curr->data[new_len - 1] = index;
}

int search(node_t *root, uint32_t address)
{
    node_t *curr = root;
    node_t *ans = NULL;
    int i = 31;
    while (curr && i) {
        uint8_t bit = (ntohl(address) & (1 << i)) >> i;
        curr = curr->children[bit];
        if (curr && curr->data_len) {
            ans = curr; // still trying to find better match
        }
        i--;
    }

    if (ans == NULL)
        return -1;
    return ans->data[0];
}
