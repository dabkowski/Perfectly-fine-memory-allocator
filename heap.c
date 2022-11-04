#include "heap.h"
#include <stdlib.h>
#include <inttypes.h>
#include "custom_unistd.h"
#include <string.h>
#include <stdio.h>

static void* start_brk = NULL;


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

    block *tail_guard = (block*)((char *)start_brk + ((PAGE_SIZE - sizeof(block))));
    block *usable_block = ((block *)start_brk + 1);
    block *front_guard = (block*)start_brk;

    tail_guard->size = 0;
    tail_guard->next = NULL;
    tail_guard->prev = usable_block;

    usable_block->size = -(int)(PAGE_SIZE - sizeof(block)*3);
    usable_block->block_size = -(int)(PAGE_SIZE - sizeof(block)*3);
    usable_block->next = tail_guard;
    usable_block->prev = front_guard;

    front_guard->size = 0;
    front_guard->next = usable_block;
    front_guard->prev = NULL;

    usable_block->chksum = front_guard->size + tail_guard->size;
    front_guard->chksum = usable_block->size;
    tail_guard->chksum = usable_block->size;

    return 0;
}



void heap_clean(void){
    if(start_brk == NULL)
        return ;
    ssize_t size = (unsigned char *) custom_sbrk(0) - (unsigned char *)start_brk;
    memset(start_brk, 0, size);
    custom_sbrk(-size);
    start_brk = NULL;
}
int extend_heap(void){
    if(custom_sbrk(PAGE_SIZE) == ((void *)-1))
        return -1;
    block *iterator = (block *)start_brk;
    while(iterator->next != NULL){
        iterator = iterator->next;
    }

    ssize_t placement = (unsigned char *)custom_sbrk(0) - (unsigned char *)start_brk - (sizeof(block));
    block *new_plug = (block *)(((unsigned char*)(start_brk)) + placement);
    new_plug->prev = iterator->prev;
    new_plug->next = NULL;
    new_plug->size = 0;

    iterator->prev->next = new_plug;
    iterator->prev->size = iterator->prev->size - PAGE_SIZE + sizeof(block); // - or +?
    iterator->prev->block_size = iterator->prev->size; // - or +?

    new_plug->chksum = new_plug->prev->size;
    iterator->prev->chksum = iterator->prev->prev->size + iterator->prev->next->size;

    return 0;
}

void correct_validation(block *iterator, int with_new_header){
    if(with_new_header) {
        if (iterator->prev->prev != NULL) {
            iterator->prev->chksum = iterator->prev->prev->size + iterator->size + iterator->prev->size;
        } else {
            iterator->prev->chksum = iterator->size + iterator->prev->size; //size = 0
        }
        if (iterator->next->next->next != NULL) {
            iterator->next->next->chksum = iterator->next->size + iterator->next->next->next->size + iterator->next->next->size;;
        } else {
            iterator->next->next->chksum = iterator->next->size + iterator->next->next->size;
        }
    }
    else{
        if (iterator->prev->prev != NULL) {
            iterator->prev->chksum = iterator->prev->prev->size + iterator->size + iterator->prev->size;
        } else {
            iterator->prev->chksum = iterator->size + iterator->prev->size;
        }
        if (iterator->next->next != NULL) {
            iterator->next->chksum = iterator->size + iterator->next->next->size + iterator->next->size;
        } else {
            iterator->next->chksum = iterator->size + iterator->next->size;
        }
    }
}

void *first_free(block *iterator, size_t size){
    while(iterator->next != NULL){
        if( -iterator->size >= (int)(ALIGN1(size) + FENCE_SIZE + FENCE_SIZE)){
            unsigned char *char_iterator = (unsigned char *)iterator;

            char_iterator += sizeof(block);
            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            //block new_header = {.prev = iterator, .next = iterator->next, .size = -(int)(iterator->size - sizeof(block) - FENCE_SIZE*2 - ALIGN1(size) - size) , .block_size = -(int)(iterator->size - sizeof(block) - FENCE_SIZE*2 - ALIGN1(size) - size)};
            if(-iterator->size >= (int)(ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + (sizeof(block) + FENCE_SIZE + FENCE_SIZE + 1 ))) {
                block *new_header = ((block *) char_iterator);

                new_header->prev = iterator;
                new_header->next = iterator->next;

                new_header->size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header->block_size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));

                iterator->next->prev = new_header;
                iterator->next = new_header;
                iterator->size = (int)size; //FENCE_SIZE*2 + sizeof(block) ; // TODO +sizeof(block) and FENCE_SIZE as well or not?
                iterator->block_size = ALIGN1(size) + FENCE_SIZE*2;

                //Validation add
                iterator->chksum = iterator->prev->size + iterator->next->size + iterator->size;
                new_header->chksum = new_header->prev->size + new_header->next->size + new_header->size;
                correct_validation(iterator,1);
            }
            else{
                iterator->size = (int)size; //FENCE_SIZE*2 + sizeof(block) ; // TODO +sizeof(block) and FENCE_SIZE as well or not?
                iterator->block_size = -iterator->block_size;

                //val
                correct_validation(iterator,0);
            }

            unsigned char *ret_val = (unsigned char*)iterator + sizeof(block) + FENCE_SIZE;
            return ret_val;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *heap_malloc(size_t size){ //check if heap hasnt been violated TODO
    if(size <= 0)
        return NULL;
    if(heap_validate() != 0)
        return NULL;
    block *iterator = (block*)start_brk;

    unsigned char *res = first_free(iterator, size);
    while(res == NULL){
        if(extend_heap() == -1)
            return NULL;
        res = first_free(iterator, size);
    }
    //res = first_free(iterator, size);
    return res;
}
void *heap_calloc(size_t number, size_t size){
    if(number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = heap_malloc(number * size);
    if(ret == NULL) return NULL;
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
    if(get_pointer_type((unsigned char*)memblock) != pointer_valid)
        return ;
    if(memblock == NULL)
        return ;
    block *header = (block *)((unsigned char *)memblock - sizeof(block) - FENCE_SIZE);
    header->size = -(header->block_size);
    header->block_size = -(header->block_size);
    coalesce();
}
int heap_validate(void){

    if(start_brk == NULL)
        return 2;

    block *iterator = (block *)start_brk;
    long long new_checksum;
    new_checksum = iterator->next->size + iterator->size;
    if(new_checksum != iterator->chksum)
        return 3;
    iterator = iterator->next;

    while(iterator->next != NULL){
        new_checksum = iterator->prev->size + iterator->next->size + iterator->size;
        if(new_checksum != iterator->chksum)
            return 3;
        if(*(int *)(iterator+1) != 0){
            return 1;
        }
        if(*(int*)((unsigned char*)iterator + iterator->size + sizeof(block)) != 0){
            return 1;
        }
        iterator = iterator->next;
    }

    new_checksum = iterator->prev->size + iterator->size;
    if(new_checksum != iterator->chksum)
        return 3;

    return 0;

}
void *heap_malloc_aligned(size_t count){
    return 0;
}
void *heap_calloc_aligned(size_t number, size_t size){
    return 0;
}
void *heap_realloc_aligned(void *memblock, size_t size){
    return 0;
}
enum pointer_type_t get_pointer_type(const void* pointer){

        if(pointer == NULL)
            return pointer_null;

        int ret = heap_validate();
        if(ret == 1 || ret == 2 || ret == 3)
            return pointer_heap_corrupted;


        block *iterator = start_brk;

        if((unsigned char *)pointer < (unsigned char *)iterator)
            return pointer_unallocated;

        while(iterator != NULL){
            if((unsigned char *)pointer < (unsigned char *)iterator){
                iterator = iterator->prev;
                break;
            }
            iterator = iterator->next;
        }
        if(iterator == NULL)
            return pointer_unallocated;

        if(iterator->size < 0 && (unsigned char *)pointer >= ((unsigned char *)iterator + sizeof(block)) && (unsigned char *)pointer <= ((unsigned char *)iterator + sizeof(block) - iterator->block_size))
            return pointer_unallocated;

        if((unsigned char *)pointer >= (unsigned char*)iterator && (unsigned char *)pointer <= ((unsigned char*)iterator+sizeof(block))){
            return pointer_control_block;
        }

        if(((unsigned char *)pointer >= ((unsigned char*)iterator+sizeof(block)) && (unsigned char *)pointer < ((unsigned char*)iterator+sizeof(block)+FENCE_SIZE)) || ((unsigned char *)pointer >= ((unsigned char*)iterator+sizeof(block)+FENCE_SIZE+iterator->size) && (unsigned char *)pointer <= ((unsigned char*)iterator+sizeof(block)+2*FENCE_SIZE+iterator->size)))
            return pointer_inside_fences;

        if(((unsigned char *)pointer == ((unsigned char*)iterator + sizeof(block) + FENCE_SIZE)))
            return pointer_valid;

        if(((unsigned char *)pointer > ((unsigned char*)iterator) + sizeof(block) + FENCE_SIZE) && ((unsigned char *)pointer <= (unsigned char*)iterator) + sizeof(block) + FENCE_SIZE + iterator->size)
            return pointer_inside_data_block;

        return pointer_unallocated;


}
size_t heap_get_largest_used_block_size(void){
    if(start_brk == NULL)
        return 0;
    if(heap_validate() != 0)
        return 0;
    size_t largest = 0;
    block *iterator = (block *)start_brk;
    while(iterator != NULL){
        if(iterator->size > (int)largest)
            largest = iterator->size;
        iterator = iterator->next;
    }
    if(largest == 0)
        return 0;
    return largest;
}