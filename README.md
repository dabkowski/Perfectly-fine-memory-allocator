# Perfectly Fine Memory Allocator

This project aims to develop a custom memory manager for efficient management of the program's heap. The memory manager
provides custom implementations of the `malloc`, `calloc`, `free`, and `realloc` functions, along with additional
utility functions for monitoring the heap's state, consistency, and defragmentation.

# Features

The memory allocator offers the following functionalities:

* **Standard Allocation/Deallocation**: The allocator provides custom versions of the `malloc`, `calloc`, `free`,
  and `realloc`
  functions that adhere to the API of the malloc family. These functions accurately replicate the behavior of their
  standard counterparts when invoked by the user's code.
* **Heap Reset**: The allocator allows for resetting the heap to its initial state, as it was when the program started.
  This feature enables a clean slate for subsequent memory allocations.
* **Dynamic Heap Expansion**: The allocator is capable of increasing the size of the heap by generating requests to the
  operating system. This ensures that the heap can grow as needed to accommodate larger memory allocations.
* **Guard Bands**: The allocator incorporates guard bands, which are special markers placed immediately before and after
  the memory blocks allocated to the user. These guard bands eliminate empty space between the user block and the guard
  markers. The guard bands consist of control structures (C), upper head markers (H), lower tail markers (T), and the
  user block (b). Violating the guard bands (overwriting their values) indicates incorrect usage of the allocated memory
  block, prompting the need for error detection and correction.
* **Word-Aligned Memory**: All memory allocation functions (`heap_malloc`, `heap_calloc`, and `heap_realloc`) return memory
  addresses that are multiples of the machine word size.

#Usage Examples

Below are some usage examples to help you get started with the custom memory allocator:

```c
#include <stdio.h>
#include "heap.h"

int main() {
    // Allocate memory
    int* ptr1 = (int*)heap_malloc(sizeof(int));
    int* ptr2 = (int*)heap_calloc(5, sizeof(int));

    // Use the allocated memory
    *ptr1 = 10;
    for (int i = 0; i < 5; ++i) {
        ptr2[i] = i;
    }

    // Deallocate memory
    heap_free(ptr1);
    heap_free(ptr2);

    return 0;
}
```