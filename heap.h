#ifndef ALOKATOR_HEAP_H
#define ALOKATOR_HEAP_H

#include <stdlib.h>

#define PAGE_SIZE 4096
#define FENCE 0xDEADBUTT
#define FENCE_SIZE 4


#define ALIGNMENT 4
#define ALIGN1(x) (((x) & ~(ALIGNMENT - 1)) + ALIGNMENT * !!((x) & (ALIGNMENT -1)))
#define ALIGN2(x) (((x) + (ALIGNMENT - 1)) & ~(ALIGNMENT -1))

typedef unsigned long long ull;

typedef struct memblock_t {
    struct memblock_t *next;
    struct memblock_t *prev;
    int size;
    int block_size;
    unsigned long chksum;
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
void *heap_malloc_aligned(size_t count);
void *heap_calloc_aligned(size_t number, size_t size);
void *heap_realloc_aligned(void *memblock, size_t size);
#endif //ALOKATOR_HEAP_H
