#ifndef BLOCK_COUNTER_H
#define BLOCK_COUNTER_H

#include <stdint.h>

#define HASH_TABLE_SIZE 1024

// Struct to store block address and execution count
typedef struct {
    void* addr; // Block address
    int count;  // Execution count
} BlockCount;

// Declaration of the block count table
extern BlockCount block_count_table[HASH_TABLE_SIZE];

// Function declarations
unsigned int hash(void* addr);
void increment_block_count(void* addr);
void print_block_counts();

#endif // BLOCK_COUNTER_H

