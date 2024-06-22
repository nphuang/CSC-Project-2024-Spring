import ctypes
import time
from pwn import *

offset = [0, 1, 2, 3, 4]

for i in offset:
    libc = ctypes.cdll.LoadLibrary("libc.so.6")

    conn = remote('140.113.24.241', 30171)

    seed = int(time.time()) + i
    libc.srand(seed)
    secret = ''
    for _ in range(16):
        secret += chr(48 + libc.rand() % (126 - 47 ) +1)
    # print(secret)
    conn.recvuntil(b"Please enter the secret: ")
    conn.sendline(secret.encode())
    response = conn.recvall()
    conn.close()
    if b"FLAG" in response:
        print(response.decode())
        break
