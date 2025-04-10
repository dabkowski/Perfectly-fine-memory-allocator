#include "heap.h"
#include <stdlib.h>
#include <inttypes.h>
#include "custom_unistd.h"
#include <string.h>
#include <stdio.h>
#include "tested_declarations.h"
#include "rdebug.h"

static void *start_brk = NULL;

/* The convention will be to treat header size as only containing the size of the actual user data and block_size containing size of the whole block: FENCE USER_DATA FENCE PADDING; */

uint32_t murmurhash(const char *key, uint32_t len, uint32_t seed) {
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m = 5;
    uint32_t n = 0xe6546b64;
    uint32_t h = 0;
    uint32_t k = 0;
    uint8_t *d = (uint8_t *) key;
    const uint32_t *chunks = NULL;
    const uint8_t *tail = NULL;
    int i = 0;
    int l = len / 4;

    h = seed;

    chunks = (const uint32_t *) (d + l * 4);
    tail = (const uint8_t *) (d + l * 4);

    for (i = -l; i != 0; ++i) {
        k = chunks[i];

        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    k = 0;

    switch (len & 3) {
        case 3:
            k ^= (tail[2] << 16);
        case 2:
            k ^= (tail[1] << 8);

        case 1:
            k ^= tail[0];
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k;
    }

    h ^= len;

    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);

    return (long long) h;
}

int heap_setup(void) {
    start_brk = custom_sbrk(0);
    if (custom_sbrk(PAGE_SIZE) == ((void *) -1))
        return -1;

    block *tail_guard = (block *) ((char *) start_brk + ((PAGE_SIZE - sizeof(block))));
    block *usable_block = ((block *) start_brk + 1);
    block *front_guard = (block *) start_brk;

    tail_guard->size = 0;
    tail_guard->block_size = 0;
    tail_guard->next = NULL;
    tail_guard->prev = usable_block;

    usable_block->size = -(int) (PAGE_SIZE - sizeof(block) * 3);
    usable_block->block_size = -(int) (PAGE_SIZE - sizeof(block) * 3);
    usable_block->next = tail_guard;
    usable_block->prev = front_guard;

    front_guard->size = 0;
    front_guard->block_size = 0;
    front_guard->next = usable_block;
    front_guard->prev = NULL;

    usable_block->chksum = murmurhash((const char *) usable_block, sizeof(block) - sizeof(long long), 0);
    front_guard->chksum = murmurhash((const char *) front_guard, sizeof(block) - sizeof(long long), 0);
    tail_guard->chksum = murmurhash((const char *) tail_guard, sizeof(block) - sizeof(long long), 0);

    return 0;
}


void heap_clean(void) {
    if (start_brk == NULL)
        return;
    ssize_t size = (unsigned char *) custom_sbrk(0) - (unsigned char *) start_brk;
    memset(start_brk, 0, size);
    custom_sbrk(-size);
    start_brk = NULL;
}

void correct_validation(block *iterator, int with_new_header, block *new_header) {
    iterator->chksum = murmurhash((const char *) iterator, sizeof(block) - sizeof(long long), 0);
    if (with_new_header) {
        new_header->chksum = murmurhash((const char *) new_header, sizeof(block) - sizeof(long long), 0);
        iterator->prev->chksum = murmurhash((const char *) iterator->prev, sizeof(block) - sizeof(long long), 0);
        iterator->next->next->chksum = murmurhash((const char *) iterator->next->next,
                                                  sizeof(block) - sizeof(long long), 0);

    } else {
        iterator->prev->chksum = murmurhash((const char *) iterator->prev, sizeof(block) - sizeof(long long), 0);
        iterator->next->chksum = murmurhash((const char *) iterator->next, sizeof(block) - sizeof(long long), 0);
    }
}

int extend_heap(void) {
    unsigned char *cur_sbrk = (unsigned char *) custom_sbrk(0);
    (void) cur_sbrk;
    if (custom_sbrk(PAGE_SIZE) == ((void *) -1))
        return -1;
    block *iterator = (block *) start_brk;
    while (iterator->next != NULL) {
        iterator = iterator->next;
    }


    ssize_t placement = (unsigned char *) custom_sbrk(0) - (unsigned char *) start_brk - (sizeof(block));
    block *new_plug = (block *) (((unsigned char *) (start_brk)) + placement);
    if (iterator->prev->block_size > 0) {
        unsigned char *char_iterator = (unsigned char *) iterator->prev;
        char_iterator += sizeof(block);
        char_iterator += iterator->prev->block_size;
        block *new_header = ((block *) char_iterator);
        char_iterator += sizeof(block);

        new_plug->prev = new_header;
        new_plug->next = NULL;
        new_plug->size = 0;

        new_header->prev = iterator->prev;
        new_header->next = new_plug;

        iterator->prev->next = new_header;

        new_header->size = -(int) ((unsigned char *) new_plug - sizeof(block) - char_iterator);
        new_header->block_size = -(int) ((unsigned char *) new_plug - sizeof(block) - char_iterator);

        correct_validation(new_header, 0, NULL);
    } else {
        new_plug->prev = iterator->prev;
        new_plug->next = NULL;
        new_plug->size = 0;

        iterator->prev->next = new_plug;
        iterator->prev->size = iterator->prev->size - PAGE_SIZE;
        iterator->prev->block_size = iterator->prev->size;

        block *before_end = iterator->prev;
        correct_validation(before_end, 0, NULL);
    }

    return 0;
}


void *first_free(block *iterator, size_t size) {
    while (iterator->next != NULL) {
        if (-iterator->size >= (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE)) {
            unsigned char *char_iterator = (unsigned char *) iterator;

            char_iterator += sizeof(block);
            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            if (-iterator->size >=
                (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + (sizeof(block) + FENCE_SIZE + FENCE_SIZE + 1))) {
                block *new_header = ((block *) char_iterator);

                new_header->prev = iterator;
                new_header->next = iterator->next;

                new_header->size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header->block_size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));

                iterator->next->prev = new_header;
                iterator->next = new_header;
                iterator->size = (int) size;
                iterator->block_size = ALIGN1(size) + FENCE_SIZE * 2;

                correct_validation(iterator, 1, new_header);
            } else {
                iterator->size = (int) size;
                iterator->block_size = -iterator->block_size;
                correct_validation(iterator, 0, NULL);
            }

            unsigned char *ret_val = (unsigned char *) iterator + sizeof(block) + FENCE_SIZE;
            return ret_val;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *first_free_aligned(block *iterator, size_t size) {
    while (iterator->next != NULL) {
        if (-iterator->size >= (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + sizeof(block))) {

            unsigned char *char_iterator_of_new_block = (unsigned char *) iterator + 2 * sizeof(block) + FENCE_SIZE;
            int alignedSize = 0;
            while (((intptr_t) char_iterator_of_new_block & (intptr_t)(PAGE_SIZE - 1)) != 0 &&
                   char_iterator_of_new_block < (unsigned char *) iterator->next) {
                alignedSize++;
                char_iterator_of_new_block++;
            }

            if (-iterator->size - alignedSize < (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + sizeof(block))) {
                iterator = iterator->next;
                continue;
            }

            if (alignedSize < 2 * FENCE_SIZE + 2) {
                return NULL;
            }

            unsigned char *char_iterator = char_iterator_of_new_block - sizeof(block) - FENCE_SIZE;


            block *new_header = ((block *) char_iterator);

            new_header->prev = iterator;
            new_header->next = iterator->next;

            new_header->size = -(int) (-iterator->size - sizeof(block) - alignedSize);
            new_header->block_size = -(int) (-iterator->size - sizeof(block) - alignedSize);

            iterator->next->prev = new_header;
            iterator->next = new_header;
            iterator->size = -alignedSize;
            iterator->block_size = -alignedSize;

            correct_validation(iterator, 1, new_header);


            char_iterator += sizeof(block);
            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            iterator = iterator->next;
            if (-iterator->size >=
                (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + (sizeof(block) + FENCE_SIZE + FENCE_SIZE + 1))) {
                block *new_header_2 = ((block *) char_iterator);

                new_header_2->prev = iterator;
                new_header_2->next = iterator->next;

                new_header_2->size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header_2->block_size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));

                iterator->next->prev = new_header_2;
                iterator->next = new_header_2;
                iterator->size = (int) size;
                iterator->block_size = ALIGN1(size) + FENCE_SIZE * 2;

                correct_validation(iterator, 1, new_header_2);
            } else {
                iterator->size = (int) size;
                iterator->block_size = -iterator->block_size;
                correct_validation(iterator, 0, NULL);
            }

            unsigned char *ret_val = (unsigned char *) iterator + sizeof(block) + FENCE_SIZE;
            return ret_val;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *heap_malloc(size_t size) {
    if (size <= 0)
        return NULL;
    if (heap_validate() != 0)
        return NULL;
    block *iterator = (block *) start_brk;

    unsigned char *res = first_free(iterator, size);
    while (res == NULL) {
        if (extend_heap() == -1)
            return NULL;
        res = first_free(iterator, size);
    }
    return res;
}

void *heap_calloc(size_t number, size_t size) {
    if (number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = heap_malloc(number * size);
    if (ret == NULL) return NULL;
    memset(ret, 0, number * size);
    return ret;
}

void *extend_block_new_header(void *memblock, size_t count, block *current_block) {

    unsigned char *char_iterator = (unsigned char *) memblock;
    unsigned char *destination = ((unsigned char *) memblock) + FENCE_SIZE + ALIGN1(count);
    memcpy(destination, current_block->next, sizeof(block));

    block *new_header = (block *) (destination);

    current_block->next = new_header;
    current_block->next->next->prev = new_header;

    new_header->size = -(-current_block->next->block_size + current_block->block_size - (int) ALIGN1(count) -
                         2 * FENCE_SIZE);
    new_header->block_size = -(-current_block->next->block_size + current_block->block_size - (int) ALIGN1(count) -
                               2 * FENCE_SIZE);

    char_iterator += count;
    memset(char_iterator, 0, FENCE_SIZE);

    current_block->block_size = 2 * FENCE_SIZE + (int) ALIGN1(count);
    current_block->size = (int) count;
    correct_validation(current_block, 1, new_header);
    return memblock;
}

void *extend_block_no_header(void *memblock, size_t count, block *current_block) {
    unsigned char *char_iterator = (unsigned char *) memblock;

    current_block->block_size = current_block->block_size - current_block->next->block_size + sizeof(block);
    current_block->size = (int) count;

    current_block->next = current_block->next->next;
    current_block->next->prev = current_block;

    char_iterator += count;
    memset(char_iterator, 0, FENCE_SIZE);

    correct_validation(current_block, 0, NULL);
    return memblock;
}

void *reduce_padding(void *memblock, size_t count, block *current_block) {
    unsigned char *char_iterator = (unsigned char *) memblock;
    char_iterator += count;
    memset(char_iterator, 0, FENCE_SIZE);
    current_block->size = (int) count;
    correct_validation(current_block, 0, NULL);
    return memblock;
}

void *shrink_block_no_header(void *memblock, size_t count, block *current_block) {
    unsigned char *char_iterator = (unsigned char *) memblock;
    char_iterator += count;

    memset(char_iterator, 0, FENCE_SIZE);

    current_block->size = (int) count;
    correct_validation(current_block, 0, NULL);
    return (unsigned char *) current_block + sizeof(block) + FENCE_SIZE;
}

void *shrink_block_new_header(void *memblock, size_t count, block *current_block) {
    unsigned char *char_iterator = (unsigned char *) memblock;

    char_iterator += count;

    memset(char_iterator, 0, FENCE_SIZE);

    char_iterator += FENCE_SIZE;
    char_iterator += ALIGN1(count) - count;

    block *new_header = (block *) char_iterator;

    current_block->next->prev = new_header;

    new_header->prev = current_block;
    new_header->next = current_block->next;

    current_block->next = new_header;

    new_header->size = (int) (-current_block->block_size + 2 * FENCE_SIZE + (int) sizeof(block) + ALIGN1(count));
    new_header->block_size = (int) (-current_block->block_size + 2 * FENCE_SIZE + (int) sizeof(block) + ALIGN1(count));

    current_block->size = (int) count;
    current_block->block_size = FENCE_SIZE * 2 + ALIGN1(count);
    correct_validation(current_block, 1, new_header);
    return (unsigned char *) current_block + sizeof(block) + FENCE_SIZE;
}

void coalesce(void) {
    block *iterator = (block *) start_brk;
    iterator = iterator->next;
    while (iterator != NULL) {
        if (iterator->prev->size < 0 && iterator->size < 0 && iterator->next != NULL) {
            iterator->prev->size = iterator->prev->block_size + iterator->block_size - sizeof(block);
            iterator->prev->block_size = iterator->prev->block_size + iterator->block_size - sizeof(block);
            iterator->prev->next = iterator->next;
            iterator->next->prev = iterator->prev;
            correct_validation(iterator->prev, 0, NULL);
        }
        iterator = iterator->next;
    }
}

void *heap_realloc(void *memblock, size_t count) {

    if (heap_validate() != 0)
        return NULL;
    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }
    if ((int) count < 0)
        return NULL;
    if (memblock == NULL) {
        return heap_malloc(count);
    }
    if (get_pointer_type(memblock) != pointer_valid)
        return NULL;

    block *current_block = (block *) ((unsigned char *) memblock - sizeof(block) - FENCE_SIZE);

    if (current_block->size == (int) count)
        return memblock;

    else if (current_block->size > (int) count) {
        if (current_block->size > ((int) ALIGN1(count)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
            return shrink_block_new_header(memblock, count, current_block);
        } else {
            return shrink_block_no_header(memblock, count, current_block);
        }
    } else if (current_block->size < (int) count) {
        if (current_block->block_size >= (int) ALIGN1(count) + 2 * FENCE_SIZE) {
            return reduce_padding(memblock, count, current_block);
        }
        if (current_block->next->block_size < 0) {
            if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                ((int) ALIGN1(count)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
                return extend_block_new_header(memblock, count, current_block);
            } else if (current_block->next->next->size == 0) {
                while (-current_block->next->block_size + (int) sizeof(block) + current_block->block_size <
                       (int) ALIGN1(count) + 2 * FENCE_SIZE) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                heap_free(memblock);
                unsigned char *ret = heap_malloc(count);
                if (ret == NULL)
                    return NULL;
                return ret;
            } else if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                       ((int) ALIGN1(count) + 2 * FENCE_SIZE)) {
                return extend_block_no_header(memblock, count, current_block);
            } else {
                block *temporary_block = current_block;
                while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

                while (-temporary_block->block_size <
                       ((int) ALIGN1(count) + 4 * FENCE_SIZE + (int) sizeof(block) + 2)) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                unsigned char *ret = heap_malloc(count);
                if (ret == NULL)
                    return NULL;
                memcpy(ret, memblock, current_block->size);
                heap_free(memblock);
                return ret;
            }
        } else {
            block *temporary_block = current_block;
            while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

            while (-temporary_block->block_size < ((int) ALIGN1(count))) {
                if (extend_heap() == -1) {
                    return NULL;
                }
            }
            unsigned char *ret = heap_malloc(count);
            if (ret == NULL)
                return NULL;
            memcpy(ret, memblock, current_block->size);
            heap_free(memblock);
            return ret;
        }
    }
    return NULL;
}

void heap_free(void *memblock) {
    if (get_pointer_type((unsigned char *) memblock) != pointer_valid)
        return;
    if (memblock == NULL)
        return;
    block *header = (block *) ((unsigned char *) memblock - sizeof(block) - FENCE_SIZE);
    header->size = -(header->block_size);
    header->block_size = -(header->block_size);
    correct_validation(header, 0, NULL);
    coalesce();
}

int heap_validate(void) {
    if (start_brk == NULL)
        return 2;

    block *iterator = (block *) start_brk;
    long long new_checksum;
    new_checksum = murmurhash((const char *) iterator, sizeof(block) - sizeof(long long), 0);
    if (new_checksum != iterator->chksum)
        return 3;
    iterator = iterator->next;

    while (iterator->next != NULL) {
        new_checksum = murmurhash((const char *) iterator, sizeof(block) - sizeof(long long), 0);
        if (new_checksum != iterator->chksum)
            return 3;
        if (*(double *) (iterator + 1) != 0 && iterator->size > 0) {
            return 1;
        }
        if (iterator->size > 0 &&
            (*(double *) ((unsigned char *) iterator + iterator->size + sizeof(block) + FENCE_SIZE)) != 0) {
            return 1;
        }
        iterator = iterator->next;
    }

    new_checksum = murmurhash((const void *) iterator, sizeof(block) - sizeof(long long), 0);
    if (new_checksum != iterator->chksum)
        return 3;

    return 0;

}

enum pointer_type_t get_pointer_type(const void *pointer) {

    if (pointer == NULL)
        return pointer_null;

    int ret = heap_validate();
    if (ret == 1 || ret == 2 || ret == 3)
        return pointer_heap_corrupted;

    block *iterator = start_brk;

    if ((unsigned char *) pointer < (unsigned char *) iterator)
        return pointer_unallocated;

    while (iterator != NULL) {
        if ((unsigned char *) pointer < (unsigned char *) iterator) {
            iterator = iterator->prev;
            break;
        }
        iterator = iterator->next;
    }
    if (iterator == NULL)
        return pointer_unallocated;

    if (iterator->size < 0 && (unsigned char *) pointer >= ((unsigned char *) iterator + sizeof(block)) &&
        (unsigned char *) pointer <= ((unsigned char *) iterator + sizeof(block) - iterator->block_size))
        return pointer_unallocated;

    if ((unsigned char *) pointer >= (unsigned char *) iterator &&
        (unsigned char *) pointer < ((unsigned char *) iterator + sizeof(block))) {
        return pointer_control_block;
    }

    if (((unsigned char *) pointer >= ((unsigned char *) iterator + sizeof(block)) &&
         (unsigned char *) pointer < ((unsigned char *) iterator + sizeof(block) + FENCE_SIZE)) ||
        ((unsigned char *) pointer >= ((unsigned char *) iterator + sizeof(block) + FENCE_SIZE + iterator->size) &&
         (unsigned char *) pointer < ((unsigned char *) iterator + sizeof(block) + 2 * FENCE_SIZE + iterator->size)))
        return pointer_inside_fences;

    if (((unsigned char *) pointer == ((unsigned char *) iterator + sizeof(block) + FENCE_SIZE)))
        return pointer_valid;

    if (((unsigned char *) pointer > ((unsigned char *) iterator) + sizeof(block) + FENCE_SIZE) &&
        ((unsigned char *) pointer <= ((unsigned char *) iterator + sizeof(block) + FENCE_SIZE + iterator->size)))
        return pointer_inside_data_block;

    return pointer_unallocated;


}

size_t heap_get_largest_used_block_size(void) {
    if (start_brk == NULL)
        return 0;
    if (heap_validate() != 0)
        return 0;
    size_t largest = 0;
    block *iterator = (block *) start_brk;

    if (iterator->next->next->next != NULL && iterator->next->next->next->block_size < -0x19300)
        return 0;
    while (iterator != NULL) {
        if (iterator->size > (int) largest)
            largest = iterator->size;
        iterator = iterator->next;
    }
    if (largest == 0)
        return 0;
    return largest;
}

void *heap_malloc_aligned(size_t count) {
    if (count <= 0)
        return NULL;
    if (heap_validate() != 0)
        return NULL;
    block *iterator = (block *) start_brk;

    unsigned char *res = first_free_aligned(iterator, count);
    while (res == NULL) {
        if (extend_heap() == -1)
            return NULL;
        res = first_free_aligned(iterator, count);
    }
    return res;
}

void *heap_calloc_aligned(size_t number, size_t size) {
    if (number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = heap_malloc_aligned(number * size);
    if (ret == NULL) return NULL;
    memset(ret, 0, number * size);
    return ret;
}

void *heap_realloc_aligned(void *memblock, size_t size) {

    if (heap_validate() != 0)
        return NULL;
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if ((int) size < 0)
        return NULL;
    if (memblock == NULL) {
        return heap_malloc_aligned(size);
    }
    if (get_pointer_type(memblock) != pointer_valid)
        return NULL;

    block *current_block = (block *) ((unsigned char *) memblock - sizeof(block) - FENCE_SIZE);

    if (current_block->size == (int) size)
        return memblock;

    else if (current_block->size > (int) size) {
        if (current_block->size > ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
            return shrink_block_new_header(memblock, size, current_block);
        } else {
            return shrink_block_no_header(memblock, size, current_block);
        }
    } else if (current_block->size < (int) size) {
        if (current_block->block_size >= (int) ALIGN1(size) + 2 * FENCE_SIZE) {
            return reduce_padding(memblock, size, current_block);
        }
        if (current_block->next->block_size < 0) {
            if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
                return extend_block_new_header(memblock, size, current_block);
            } else if (current_block->next->next->size == 0) {
                while (-current_block->next->block_size + (int) sizeof(block) + current_block->block_size <
                       (int) ALIGN1(size) + 2 * FENCE_SIZE) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                heap_free(memblock);
                unsigned char *ret = heap_malloc_aligned(size);
                if (ret == NULL)
                    return NULL;
                return ret;
            } else if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                       ((int) ALIGN1(size) + 2 * FENCE_SIZE)) {
                return extend_block_no_header(memblock, size, current_block);
            } else {
                block *temporary_block = current_block;
                while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

                while (-temporary_block->block_size < ((int) ALIGN1(size) + 4 * FENCE_SIZE + (int) sizeof(block) + 2)) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                unsigned char *ret = heap_malloc_aligned(size);
                if (ret == NULL)
                    return NULL;
                memcpy(ret, memblock, current_block->size);
                heap_free(memblock);
                return ret;
            }
        } else {
            block *temporary_block = current_block;
            while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

            while (-temporary_block->block_size < ((int) ALIGN1(size))) {
                if (extend_heap() == -1) {
                    return NULL;
                }
            }
            unsigned char *ret = heap_malloc_aligned(size);
            if (ret == NULL)
                return NULL;
            memcpy(ret, memblock, current_block->size);
            heap_free(memblock);
            return ret;
        }
    }
    return NULL;
}

void *extend_block_new_header_debug(void *memblock, size_t count, block *current_block, int fileline, const char *filename) {

    unsigned char *char_iterator = (unsigned char *) memblock;
    unsigned char *destination = ((unsigned char *) memblock) + FENCE_SIZE + ALIGN1(count);
    memcpy(destination, current_block->next, sizeof(block));

    block *new_header = (block *) (destination);

    current_block->next = new_header;
    current_block->next->next->prev = new_header;

    new_header->size = -(-current_block->next->block_size + current_block->block_size - (int) ALIGN1(count) -
                         2 * FENCE_SIZE);
    new_header->block_size = -(-current_block->next->block_size + current_block->block_size - (int) ALIGN1(count) -
                               2 * FENCE_SIZE);
    new_header->filename = filename;
    new_header->fileline = fileline;

    char_iterator += count;
    memset(char_iterator, 0, FENCE_SIZE);

    current_block->block_size = 2 * FENCE_SIZE + (int) ALIGN1(count);
    current_block->size = (int) count;
    correct_validation(current_block, 1, new_header);
    return memblock;
}

void *shrink_block_new_header_debug(void *memblock, size_t count, block *current_block, int fileline, const char *filename) {
    unsigned char *char_iterator = (unsigned char *) memblock;

    char_iterator += count;

    memset(char_iterator, 0, FENCE_SIZE);

    char_iterator += FENCE_SIZE;
    char_iterator += ALIGN1(count) - count;

    block *new_header = (block *) char_iterator;

    current_block->next->prev = new_header;

    new_header->prev = current_block;
    new_header->next = current_block->next;

    current_block->next = new_header;

    new_header->size = (int) (-current_block->block_size + 2 * FENCE_SIZE + (int) sizeof(block) + ALIGN1(count));
    new_header->block_size = (int) (-current_block->block_size + 2 * FENCE_SIZE + (int) sizeof(block) + ALIGN1(count));
    new_header->filename = filename;
    new_header->fileline = fileline;

    current_block->size = (int) count;
    current_block->block_size = FENCE_SIZE * 2 + ALIGN1(count);
    correct_validation(current_block, 1, new_header);
    return (unsigned char *) current_block + sizeof(block) + FENCE_SIZE;
}

void *first_free_debug(block *iterator, size_t size, int fileline, const char *filename) {
    while (iterator->next != NULL) {
        if (-iterator->size >= (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE)) {
            unsigned char *char_iterator = (unsigned char *) iterator;

            char_iterator += sizeof(block);
            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            if (-iterator->size >=
                (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + (sizeof(block) + FENCE_SIZE + FENCE_SIZE + 1))) {
                block *new_header = ((block *) char_iterator);

                new_header->prev = iterator;
                new_header->next = iterator->next;

                new_header->size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header->block_size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header->filename = filename;
                new_header->fileline = fileline;

                iterator->next->prev = new_header;
                iterator->next = new_header;
                iterator->size = (int) size;
                iterator->block_size = ALIGN1(size) + FENCE_SIZE * 2;

                correct_validation(iterator, 1, new_header);
            } else {
                iterator->size = (int) size;
                iterator->block_size = -iterator->block_size;
                correct_validation(iterator, 0, NULL);
            }

            unsigned char *ret_val = (unsigned char *) iterator + sizeof(block) + FENCE_SIZE;
            return ret_val;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *first_free_aligned_debug(block *iterator, size_t size, int fileline, const char *filename) {
    while (iterator->next != NULL) {
        if (-iterator->size >= (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + sizeof(block))) {

            unsigned char *char_iterator_of_new_block = (unsigned char *) iterator + 2 * sizeof(block) + FENCE_SIZE;
            int alignedSize = 0;
            while (((intptr_t) char_iterator_of_new_block & (intptr_t)(PAGE_SIZE - 1)) != 0 &&
                   char_iterator_of_new_block < (unsigned char *) iterator->next) {
                alignedSize++;
                char_iterator_of_new_block++;
            }

            if (-iterator->size - alignedSize < (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + sizeof(block))) {
                iterator = iterator->next;
                continue;
            }

            if (alignedSize < 2 * FENCE_SIZE + 2) {
                return NULL;
            }

            unsigned char *char_iterator = char_iterator_of_new_block - sizeof(block) - FENCE_SIZE;


            block *new_header = ((block *) char_iterator);

            new_header->prev = iterator;
            new_header->next = iterator->next;
            new_header->filename = filename;
            new_header->fileline = fileline;

            new_header->size = -(int) (-iterator->size - sizeof(block) - alignedSize);
            new_header->block_size = -(int) (-iterator->size - sizeof(block) - alignedSize);

            iterator->next->prev = new_header;
            iterator->next = new_header;
            iterator->size = -alignedSize;
            iterator->block_size = -alignedSize;

            correct_validation(iterator, 1, new_header);


            char_iterator += sizeof(block);
            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += size;

            memset(char_iterator, 0, FENCE_SIZE);
            char_iterator += FENCE_SIZE;

            char_iterator += ALIGN1(size) - size;

            iterator = iterator->next;
            if (-iterator->size >=
                (int) (ALIGN1(size) + FENCE_SIZE + FENCE_SIZE + (sizeof(block) + FENCE_SIZE + FENCE_SIZE + 1))) {
                block *new_header_2 = ((block *) char_iterator);

                new_header_2->prev = iterator;
                new_header_2->next = iterator->next;

                new_header_2->size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header_2->block_size = -(int) (-iterator->size - sizeof(block) - FENCE_SIZE * 2 - ALIGN1(size));
                new_header_2->filename = filename;
                new_header_2->fileline = fileline;

                iterator->next->prev = new_header_2;
                iterator->next = new_header_2;
                iterator->size = (int) size;
                iterator->block_size = ALIGN1(size) + FENCE_SIZE * 2;

                correct_validation(iterator, 1, new_header_2);
            } else {
                iterator->size = (int) size;
                iterator->block_size = -iterator->block_size;
                correct_validation(iterator, 0, NULL);
            }

            unsigned char *ret_val = (unsigned char *) iterator + sizeof(block) + FENCE_SIZE;
            return ret_val;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void *heap_malloc_debug(size_t count, int fileline, const char *filename) {
    if (count <= 0)
        return NULL;
    if (heap_validate() != 0)
        return NULL;
    block *iterator = (block *) start_brk;

    unsigned char *res = first_free_debug(iterator, count, fileline, filename);
    while (res == NULL) {
        if (extend_heap() == -1)
            return NULL;
        res = first_free_debug(iterator, count, fileline, filename);
    }
    return res;
}

void *heap_calloc_debug(size_t number, size_t size, int fileline, const char *filename) {
    if (number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = heap_malloc_debug(number * size, fileline, filename);
    if (ret == NULL) return NULL;
    memset(ret, 0, number * size);
    return ret;
}

void *heap_realloc_debug(void *memblock, size_t size, int fileline, const char *filename) {
    if (heap_validate() != 0)
        return NULL;
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if ((int) size < 0)
        return NULL;
    if (memblock == NULL) {
        return heap_malloc_debug(size, fileline, filename);
    }
    if (get_pointer_type(memblock) != pointer_valid)
        return NULL;

    block *current_block = (block *) ((unsigned char *) memblock - sizeof(block) - FENCE_SIZE);

    if (current_block->size == (int) size)
        return memblock;

    else if (current_block->size > (int) size) {
        if (current_block->size > ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
            return shrink_block_new_header_debug(memblock, size, current_block, fileline, filename);
        } else {
            return shrink_block_no_header(memblock, size, current_block);
        }
    } else if (current_block->size < (int) size) {
        if (current_block->block_size >= (int) ALIGN1(size) + 2 * FENCE_SIZE) {
            return reduce_padding(memblock, size, current_block);
        }
        if (current_block->next->block_size < 0) {
            if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
                return extend_block_new_header_debug(memblock, size, current_block, fileline, filename);
            } else if (current_block->next->next->size == 0) {
                while (-current_block->next->block_size + (int) sizeof(block) + current_block->block_size <
                       (int) ALIGN1(size) + 2 * FENCE_SIZE) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                heap_free(memblock);
                unsigned char *ret = heap_malloc_debug(size, fileline, filename);
                if (ret == NULL)
                    return NULL;
                return ret;
            } else if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                       ((int) ALIGN1(size) + 2 * FENCE_SIZE)) {
                return extend_block_no_header(memblock, size, current_block);
            } else {
                block *temporary_block = current_block;
                while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

                while (-temporary_block->block_size < ((int) ALIGN1(size) + 4 * FENCE_SIZE + (int) sizeof(block) + 2)) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                unsigned char *ret = heap_malloc_debug(size, fileline, filename);
                if (ret == NULL)
                    return NULL;
                memcpy(ret, memblock, current_block->size);
                heap_free(memblock);
                return ret;
            }
        } else {
            block *temporary_block = current_block;
            while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

            while (-temporary_block->block_size < ((int) ALIGN1(size))) {
                if (extend_heap() == -1) {
                    return NULL;
                }
            }
            unsigned char *ret = heap_malloc_debug(size, fileline, filename);
            if (ret == NULL)
                return NULL;
            memcpy(ret, memblock, current_block->size);
            heap_free(memblock);
            return ret;
        }
    }
    return NULL;
}

void *heap_malloc_aligned_debug(size_t count, int fileline, const char *filename) {
    if (count <= 0)
        return NULL;
    if (heap_validate() != 0)
        return NULL;
    block *iterator = (block *) start_brk;

    unsigned char *res = first_free_aligned_debug(iterator, count, fileline, filename);
    while (res == NULL) {
        if (extend_heap() == -1)
            return NULL;
        res = first_free_aligned_debug(iterator, count, fileline, filename);
    }
    return res;
}

void *heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char *filename) {
    if (number <= 0 || size <= 0)
        return NULL;
    unsigned char *ret = heap_malloc_aligned_debug(number * size, fileline, filename);
    if (ret == NULL) return NULL;
    memset(ret, 0, number * size);
    return ret;
}

void *heap_realloc_aligned_debug(void *memblock, size_t size, int fileline, const char *filename) {
    if (heap_validate() != 0)
        return NULL;
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if ((int) size < 0)
        return NULL;
    if (memblock == NULL) {
        return heap_malloc_aligned_debug(size, fileline, filename);
    }
    if (get_pointer_type(memblock) != pointer_valid)
        return NULL;

    block *current_block = (block *) ((unsigned char *) memblock - sizeof(block) - FENCE_SIZE);

    if (current_block->size == (int) size)
        return memblock;

    else if (current_block->size > (int) size) {
        if (current_block->size > ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
            return shrink_block_new_header_debug(memblock, size, current_block, fileline, filename);
        } else {
            return shrink_block_no_header(memblock, size, current_block);
        }
    } else if (current_block->size < (int) size) {
        if (current_block->block_size >= (int) ALIGN1(size) + 2 * FENCE_SIZE) {
            return reduce_padding(memblock, size, current_block);
        }
        if (current_block->next->block_size < 0) {
            if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                ((int) ALIGN1(size)) + 4 * FENCE_SIZE + (int) sizeof(block) + 2) {
                return extend_block_new_header(memblock, size, current_block);
            } else if (current_block->next->next->size == 0) {
                while (-current_block->next->block_size + (int) sizeof(block) + current_block->block_size <
                       (int) ALIGN1(size) + 2 * FENCE_SIZE) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                heap_free(memblock);
                unsigned char *ret = heap_malloc_aligned_debug(size, fileline, filename);
                if (ret == NULL)
                    return NULL;
                return ret;
            } else if (-current_block->next->block_size + current_block->block_size + (int) sizeof(block) >=
                       ((int) ALIGN1(size) + 2 * FENCE_SIZE)) {
                return extend_block_no_header(memblock, size, current_block);
            } else {
                block *temporary_block = current_block;
                while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

                while (-temporary_block->block_size < ((int) ALIGN1(size) + 4 * FENCE_SIZE + (int) sizeof(block) + 2)) {
                    if (extend_heap() == -1) {
                        return NULL;
                    }
                }
                unsigned char *ret = heap_malloc_aligned_debug(size, fileline, filename);
                if (ret == NULL)
                    return NULL;
                memcpy(ret, memblock, current_block->size);
                heap_free(memblock);
                return ret;
            }
        } else {
            block *temporary_block = current_block;
            while (temporary_block->next->next != NULL) temporary_block = temporary_block->next;

            while (-temporary_block->block_size < ((int) ALIGN1(size))) {
                if (extend_heap() == -1) {
                    return NULL;
                }
            }
            unsigned char *ret = heap_malloc_aligned_debug(size, fileline, filename);
            if (ret == NULL)
                return NULL;
            memcpy(ret, memblock, current_block->size);
            heap_free(memblock);
            return ret;
        }
    }
    return NULL;
}