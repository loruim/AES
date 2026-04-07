from aes import AES
from FileRead import encrypt_file, decrypt_file
import time

# 128, 192, 256
#key = 0x2b7e151628aed2a6abf7158809cf4f3c
#key = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
#key = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4

start_time = time.time()
if __name__ == "__main__":
    key = b'\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4'
    aes = AES(key)
    encrypt_file("input.txt", "ciphertext.txt", aes)
    decrypt_file("ciphertext.txt", "decodetext.txt", aes)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"============================ {execution_time} ============================")
