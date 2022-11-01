#include "heap.h"
#include <stdlib.h>
#include <inttypes.h>
#include "custom_unistd.h"
#include <string.h>
#include <stdio.h>

static void* start_brk;



/*The convention will be to treat the header size as only containing the size of the actual user data;
 *
 *
 *
 *
 * */

// TODO Should each block size include size of the fences and next header or only user data?
int heap_setup(void){
    start_brk = custom_sbrk(0);
    if(custom_sbrk(PAGE_SIZE) == ((void *)-1))
        return -1;

    block tail_guard = {.size = 0, .next = NULL};
    block usable_block = {.size = -(int)(PAGE_SIZE - sizeof(block)*2), .block_size = -(int)(PAGE_SIZE - sizeof(block)*2), .next = &tail_guard};
    block front_guard = {.size = 0, .next = &usable_block, .prev = NULL, .chksum = -(int)(PAGE_SIZE - sizeof(block)*2)};
    usable_block.prev = &front_guard;
    tail_guard.prev = &usable_block;

    *(block *)start_brk = front_guard;
    *((block *)((char *)start_brk + ((PAGE_SIZE - sizeof(block))))) = tail_guard;
    *((block *)start_brk + 1) = usable_block;

    memset(((block *)start_brk + 1), 0, (int)(PAGE_SIZE - sizeof(block)));

    return 0;
}



void heap_clean(void){
    ssize_t size = (ssize_t *)custom_sbrk(0) - (ssize_t *)start_brk;
    memset(start_brk, 0, size);
    custom_sbrk(-size);
}
int extend_heap(void){
    if(custom_sbrk(PAGE_SIZE) == ((void *)-1))
        return -1;
    block *iterator = (block *)start_brk;
    while(iterator->size != 0 && iterator->prev != NULL){
        iterator = iterator->next;
    }

    block new_plug = {.prev = iterator->prev, .next = NULL, .size = 0};
    iterator->prev->next = &new_plug;

    iterator->prev->size = iterator->prev->size - PAGE_SIZE + sizeof(block); // - or +?
    iterator->prev->block_size = iterator->prev->size - PAGE_SIZE + sizeof(block); // - or +?

    ssize_t placement = (ssize_t *)custom_sbrk(0) - (ssize_t *)start_brk - (ssize_t)(sizeof(block));
    *((block *)((unsigned char*)(start_brk) + placement)) = new_plug;
    return 0;
}

void *first_free(block *iterator, size_t size){
    while(iterator != NULL){
        if( (unsigned long long)-iterator->size >= (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + sizeof(block))){
            unsigned char *char_iterator = (unsigned char *)iterator;

            char_iterator += sizeof(block);
            *char_iterator = 0;
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            *char_iterator = 0;
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            block new_header = {.prev = iterator, .next = iterator->next, .size = -(int)(iterator->size - sizeof(block) - FENCE_SIZE*2 - ALIGN1(size) - size) , .block_size = -(int)(iterator->size - sizeof(block) - FENCE_SIZE*2 - ALIGN1(size) - size)};
            *(block *)char_iterator = new_header;
            iterator->size = (int)size; //FENCE_SIZE*2 + sizeof(block) ; // TODO +sizeof(block) and FENCE_SIZE as well or not?
            iterator->block_size = ALIGN1(size) + FENCE_SIZE*2;

            return char_iterator+sizeof(block)+FENCE_SIZE;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *heap_malloc(size_t size){ //check if heap hasnt been violated TODO
    if(size <= 0)
        return NULL;
    block *iterator = (block*)start_brk;

    unsigned char *res = first_free(iterator, size);
    if(res == NULL){
        if(extend_heap() == -1)
            return NULL;
    }
    res = first_free(iterator, size);
    return res;

}
void *heap_calloc(size_t number, size_t size){
    if(number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = malloc(number * size);
    memset(ret, 0, number*size);
    return ret;
}

/* REALLOC UTILS */
void *extend_block(void *memblock, size_t count, block *current_block){

    unsigned char *char_iterator = (unsigned char *)memblock;
    unsigned char *destination = ((unsigned char *)memblock) + FENCE_SIZE + ALIGN1(count);
    memcpy(destination, current_block->next, sizeof(block));
    ((block*)(destination))->prev = current_block;
    ((block*)(destination))->next = current_block->next->next;
    current_block->next = ((block*)(destination));

    ((block*)(destination))->size = current_block->next->block_size + (int)sizeof(block) + 2*FENCE_SIZE + (int)ALIGN1(count);
    ((block*)(destination))->block_size = current_block->next->block_size + (int)sizeof(block) + 2*FENCE_SIZE + (int)ALIGN1(count);


    char_iterator += count;
    *char_iterator = 0;

    current_block->block_size = 2 * FENCE_SIZE + (int) ALIGN1(count);
    current_block->size = (int)count;
    return memblock;
}

void *reduce_padding(void *memblock, size_t count, block *current_block){
    unsigned char *char_iterator = (unsigned char *)memblock;
    char_iterator+=count;
    *char_iterator = 0;
    current_block->size = (int)count; //block_size stays the same
    return memblock;
}
void *shrink_block(void *memblock, size_t count, block *current_block){
    unsigned char *char_iterator = (unsigned char *)memblock;
    char_iterator += count;

    *char_iterator = 0;
    //TODO What aboud padding? (header)(fence)(3 bytes of user data)(fence)(7 bytes of padding?)(new_header) will it be already aligned?

    //current_block->block_size = 2*FENCE_SIZE + ALIGN1(current_block->size); // block size will stay the same?
    current_block->size = (int)count;
    return (unsigned char *)current_block + FENCE_SIZE;
}

void *heap_realloc(void *memblock, size_t count){
    if(count <= 0)
        return NULL;

    //validate the heap integrity first, return NULL if corrupted

    if(memblock == NULL){
        return malloc(count);
    }

    block *current_block = (block *)((unsigned char *)memblock - sizeof(block) - FENCE_SIZE);

    if((unsigned long long)current_block->size == count) //ALIGN1(count) + FENCE_SIZE*2 + sizeof(block)?
        return memblock;

    else if((unsigned long long)current_block->size > count){
        return shrink_block(memblock, count, current_block);
    }
    else if((unsigned long long)current_block->size < count){ //remember that you can reduce padding as well
        if(ALIGN1(current_block->size) >= (int)count){
            return reduce_padding(memblock, count, current_block);
        }
        //no space for new size in the current block, check if adjacent block is free and of enough size
        if(current_block->next->block_size < 0)
        {
            if (-current_block->next->block_size + current_block->block_size - sizeof(block) - 2 * FENCE_SIZE >= count)
            {
                return extend_block(memblock, count, current_block);
            }
            //check if the next block is a plug indicating end of heap
            else if(current_block->next->next->size == 0){
                if(extend_heap() == -1)
                    return NULL;
                return extend_block(memblock, count, current_block);
            }
        }
        else{
            unsigned char *ret = malloc(count);
            if(ret == NULL)
                return NULL;
            memcpy(ret, memblock, current_block->size);
            return ret;
        }
    }
    return NULL;
}

void coalesce(void){
    block *iterator = (block *)start_brk;
    iterator = iterator->next;
    while(iterator != NULL){
        if(iterator->prev->size < 0 && iterator->size < 0){
            iterator->prev->size = iterator->prev->size + iterator->size;
            iterator->prev->next = iterator->next;
        }
        iterator = iterator->next;
    }

}
void heap_free(void *memblock){
    if(memblock == NULL)
        return ;
    block *header = (block *)((unsigned char *)memblock - sizeof(block));
    header->size = -(header->size);
    coalesce();
}
int heap_validate(void);
void *heap_malloc_aligned(size_t count);
void *heap_calloc_aligned(size_t number, size_t size);
void *heap_realloc_aligned(void *memblock, size_t size);
enum pointer_type_t get_pointer_type(const void* pointer);
size_t heap_get_largest_used_block_size(void);