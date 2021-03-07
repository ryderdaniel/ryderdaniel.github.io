from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify
from hashlib import md5
import os
from tqdm import tqdm
from time import time

keyspace  = []
for b1 in tqdm(range(256)):
    for b2 in range(256):
        for b3 in range(256):
            key = b'' + b1.to_bytes(1,'big') + b2.to_bytes(1,'big') + b3.to_bytes(1,'big')
            keyspace.append(md5(key).digest())

def prep(iv1, iv2, load):
    return b":".join([hexlify(x) for x in [iv1, iv2, load]]).decode()

def clean(inp):
    return [unhexlify(x) for x in inp.strip().split(b':')]

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def encrypt_ecb(key,text):
    cipher = AES.new(key,AES.MODE_ECB)
    return cipher.encrypt(text)

def decrypt_ecb(key, text):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(text)

# IDEA:
# Phase 1
#   - Encrypt p_1
#       - Obtain IV1
#       - Obtain IV2
#       - Obtain c_1
#   - Decrypt c_1 with IV1 = 0 and IV2 same as what was obtained in previous step
#       - Obtain p_2
# Phase 2
#   - For each key in the key space, encrypt p_1 and p_2 and save it in sets A and B
#   - xor every element in A with IV1 and if it is equal to some element in B, then we now have k1
# Phase 3
#   - With k1, encrypt empty bytes, and pass that to the encrypt function as plaintext.
#       - Obtain IV1_2 which is the input for the CBC block.
#       - Obtain IV2_2
#       - Obtain c_1_2
# Phase 4
#   - Get encrypted flag and drop connection
#   - Meet in the middle. first by trying to encrypt IV1_2 with all possible k2 and put into set C.
#     Then encrypt IV2_2 and xor with c_1_2. If the result of the xor shows up in C, then all three keys
#     Are found.
#   - Decrypt the flag
# Phase 5
#   - Profit

r = remote("crypto.ctf.zer0pts.com", 10929)

p_1 = b'\x00'*16

print("PHASE 1")

r.recvuntil('> ')
r.sendline(b'1')
r.recvuntil(': ')
r.sendline(hexlify(p_1))
r.recvuntil(': ')
iv1, iv2, c_1 = clean(r.recvline())

r.recvuntil('> ')
r.sendline('2')
r.recvuntil(': ')
package = prep(p_1, iv2, c_1)
print(package)
r.sendline(package)
r.recvuntil(': ')
p_2 = unhexlify(r.recvline().strip())

print("p_1", p_1)
print("p_2",p_2)
print("iv1", iv1)
print("iv2", iv2)
print("c_1", c_1)

print("\nPHASE 2")

k_1 = None
t1 = time()
print("Creating Table...")
for key in keyspace:
    a = byte_xor(encrypt_ecb(key, p_2),iv1)
    b = encrypt_ecb(key, p_1)
    if a == b:
        print("KEY 1 FOUND!!!")
        k_1 = key
        break
print("Time taken (seconds):", time()-t1)
print("k_1", k_1)

print("\nPHASE 3")

empty = decrypt_ecb(k_1, p_1)
r.recvuntil('> ')
r.sendline('1')
r.recvuntil(': ')
r.sendline(hexlify(empty))
r.recvuntil(': ')
iv1_2, iv2_2, c_1_2 = clean(r.recvline())

print("iv1_2", iv1_2)
print("iv2_2", iv2_2)
print("c_1_2", c_1_2)

print("\nPHASE 4")

r.recvuntil('> ')
r.sendline('3')
r.recvuntil(': ')
iv1_flag, iv2_flag, c_flag = clean(r.recvline())
r.close()

k_2 = None
k_3 = None
keymap = dict()
print("Searching for keys...")
for i in tqdm(range(len(keyspace))):
    key = keyspace[i]
    a = encrypt_ecb(key,iv1_2)
    b = byte_xor(encrypt_ecb(key,iv2_2), c_1_2)
    if a in keymap:
        print("KEYS FOUND!!")
        k_3 = keymap[a]
        k_2 = key
        break
    if b in keymap:
        print("KEYS FOUND!!")
        k_3 = key
        k_2 = keymap[b]
        break
    keymap[a] = key
    keymap[b] = key

print("k_1", k_1)
print("k_2", k_2)
print("k_3", k_3)

print("\nPHASE 5")

def get_ciphers(iv1, iv2, k1,k2,k3):
    return [
        AES.new(k1, mode=AES.MODE_ECB),
        AES.new(k2, mode=AES.MODE_CBC, iv=iv1),
        AES.new(k3, mode=AES.MODE_CFB, iv=iv2, segment_size=8*16),
    ]

def decrypt(c: bytes, iv1: bytes, iv2: bytes,keys) -> bytes:
    assert len(c) % 16 == 0
    ciphers = get_ciphers(iv1, iv2,keys[0],keys[1],keys[2])
    m = c
    for cipher in ciphers[::-1]:
        m = cipher.decrypt(m)
    return m

print(decrypt(c_flag, iv1_flag,iv2_flag,[k_1,k_2,k_3]))
