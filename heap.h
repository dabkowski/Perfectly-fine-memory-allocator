#ifndef ALOKATOR_HEAP_H
#define ALOKATOR_HEAP_H

#include <stdlib.h>
#include <stdint.h>

#define PAGE_SIZE 4096
#define FENCE_SIZE 4

#define ALIGNMENT 4
#define ALIGN1(x) (((x) & ~(ALIGNMENT - 1)) + ALIGNMENT * !!((x) & (ALIGNMENT -1)))

typedef struct memblock_t {
    struct memblock_t *next;
    struct memblock_t *prev;
    int size;
    int block_size;
    long long chksum;
} block;


enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

enum pointer_type_t get_pointer_type(const void* pointer);
size_t heap_get_largest_used_block_size(void);
int heap_setup(void);
void heap_clean(void);
void *heap_malloc(size_t size);
void *heap_calloc(size_t number, size_t size);
void *heap_realloc(void *memblock, size_t count);
void heap_free(void *memblock);
int heap_validate(void);
uint32_t murmurhash (const char *key, uint32_t len, uint32_t seed);
void correct_validation(block *iterator, int with_new_header, block *new_header);
int extend_heap(void);
void *first_free(block *iterator, size_t size);
void *extend_block_new_header(void *memblock, size_t count, block *current_block);
void *extend_block_no_header(void *memblock, size_t count, block *current_block);
void *reduce_padding(void *memblock, size_t count, block *current_block);
void *shrink_block(void *memblock, size_t count, block *current_block);
void coalesce(void);

#endif //ALOKATOR_HEAP_H
