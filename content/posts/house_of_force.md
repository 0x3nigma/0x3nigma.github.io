+++
date = '2025-10-06T00:17:12+05:30'
draft = true
title = 'House_of_force'
+++


## House Of Force

This is the first entry in a series of blogs where I try to explain various heap exploitation techniques.Today we will be looking at house of force technique.

### A little bit of history

The concept of house of force was first discussed in the paper "The Malloc Maleficarum" published by Phantasmal Phantasmagoria in the year 2005.

Did that twist your tongue while reading?? A really cool set of names right ? Okay back to where we were.

This paper introduced several heap exploitation techniques under the naming convention of "House of XXX" such as House of Lore, House of Spirit,etc and of-course House of Force.

### The Heap
Before learning about this exploitation technique we need to know a bit about the target that we are trying to exploit that is the heap(the wilderness).

The heap is a large contiguous block of memory . The heap stores dynamically allocated variables whose size is unknown to us during compile time. In C we request memory using `malloc()` and return it to the memory when not needed using `free()` . Forgetting to deallocate lead to memory leaks. In languages like Python we don't have to worry about it since this job is done automatically by the garbage collectors. 

We will try to understand the heap using a program. The source code for the program is  given below.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    char* a = malloc(24);
    char* b = malloc(24);
    char* c = malloc(24);

    // Check if allocation succeeded
    if (a == NULL || b == NULL || c == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    printf("%s", "Enter the first string: ")k
    scanf("%s", a)

    printf("%s", "Enter the second string: ")
    scanf("%s", b)

    printf("%s", "Enter the third string: ")
    scanf("%s", c)
    
    return 0;
}
```
Now we will compile using any glibc version less than 2.9 since top chunk size fields are not subject to any integrity checks during allocations.
After compiling this program we will open the binary in pwndbg.



