

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def pad_key(key):
    return key.ljust(32)[:32]

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(cipher.iv)
        f.write(encrypted_data)
    
    os.remove(file_path)  # Delete the original file after encryption

def decrypt_file(file_path, key, in_memory=False):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    if in_memory:
        return decrypted_data
    with open(file_path[:-4], 'wb') as f:
        f.write(decrypted_data)
    
    os.remove(file_path)  # Delete the encrypted file after decryption

def encrypt(dir, key=None):
    if key is None:
        # get input from user
        key = input("Enter key: ")

    key = pad_key(key)
    for root, _, files in os.walk(dir):
        for file in files:
            if file.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key)

def decrypt(dir, key=None):
    if key is None:
        key = input("Enter key: ")


    print("old key: ", key)
    key = pad_key(key)
    print("new key: ", key)
    for root, _, files in os.walk(dir):
        for file in files:
            if file.endswith(('.jpg.enc', '.jpeg.enc', '.png.enc', '.gif.enc')):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)

#encrypt("test", "A")
decrypt("test", "A")
