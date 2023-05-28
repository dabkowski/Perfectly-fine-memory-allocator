#ifndef ALLOCATOR_HEAP_H
#define ALLOCATOR_HEAP_H

#include <stdlib.h>
#include <stdint.h>

#define PAGE_SIZE 4096
#define FENCE_SIZE 8

#define ALIGNMENT sizeof(void *)
#define ALIGN1(x) (((x) & ~(ALIGNMENT - 1)) + ALIGNMENT * !!((x) & (ALIGNMENT -1)))

typedef struct memblock_t {
    struct memblock_t *next;
    struct memblock_t *prev;
    int size;
    int block_size;
    int fileline;
    const char *filename;
    long long chksum;
} block;


enum pointer_type_t {
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
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void *memblock, size_t count);
void heap_free(void *memblock);
int heap_validate(void);
uint32_t murmurhash (const char *key, uint32_t len, uint32_t seed);
void correct_validation(block *iterator, int with_new_header, block *new_header);
int extend_heap(void);
void* first_free(block *iterator, size_t size);
void* first_free_aligned(block *iterator, size_t size);
void* extend_block_new_header(void *memblock, size_t count, block *current_block);
void* extend_block_no_header(void *memblock, size_t count, block *current_block);
void* reduce_padding(void *memblock, size_t count, block *current_block);
void* shrink_block(void *memblock, size_t count, block *current_block);
void coalesce(void);
void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);

void* heap_malloc_debug(size_t count, int fileline, const char* filename);
void* heap_calloc_debug(size_t number, size_t size, int fileline, const char* filename);
void* heap_realloc_debug(void* memblock, size_t size, int fileline, const char* filename);

void* heap_malloc_aligned_debug(size_t count, int fileline, const char* filename);
void* heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char* filename);
void* heap_realloc_aligned_debug(void* memblock, size_t size, int fileline, const char* filename);

void *first_free_debug(block *iterator, size_t size, int fileline, const char* filename);
void *first_free_aligned_debug(block *iterator, size_t size, int fileline, const char* filename);
void *extend_block_new_header_debug(void *memblock, size_t count, block *current_block, int fileline, const char *filename);
void *shrink_block_new_header_debug(void *memblock, size_t count, block *current_block, int fileline, const char* filename);

#endif //ALLOCATOR_HEAP_H
