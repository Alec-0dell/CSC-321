#Andrew Okelund
import Crypto
import Crypto.Cipher
import Crypto.Cipher.AES as AES 
import math
import os

from Crypto.Util.Padding import pad 

#Read in bmp file
#Pad bmp file if necessary
#Create blocks of 128 bits
Crypto.Cipher.AES
def main():
    file_path = "cp-logo.bmp"
    body, header = reader(file_path)
    blocks = create_blocks(body)

    # ECB FUNCTIONS
    ecb_encrypted, ecb_key = ecb(blocks)
    ecb_d = ecb_decrypt(ecb_key, ecb_encrypted)
    writer('cp-logo-ENcrypted-ECB.bmp', header, ecb_encrypted)
    writer('cp-logo-DEcrypted-ECB.bmp', header, ecb_d)

    # CBC FUNCTIONS
    cbc_encrypted, cbc_key = cbc(blocks)
    cbc_d = cbc_decrypt(cbc_key, cbc_encrypted)
    writer('cp-logo-ENcrypted-CBC.bmp', header, cbc_encrypted)
    writer('cp-logo-DEcrypted-CBC.bmp', header, cbc_d)
    
    return 

def reader(file_path):
  
    with open(file_path, "rb") as file:
        header = file.read(54)
        body = file.read()
    
    body_length  = len(body)  
    pad_test = body_length % 16

    if pad_test != 0:
        pad_length = 16 - pad_test
        padding = bytes([pad_length] * pad_length)
        padded_body = body + padding
        return padded_body, header
    return body, header

def create_blocks(body):
    blocks = [body[i:i + 16] for i in range(0, len(body), 16)]
    return blocks

def ecb(data):
    key = os.urandom(16)
    cipher = AES.new(key,AES.MODE_ECB)
    encrypted = b''
    for p in data:
        cipher_text = cipher.encrypt(p)
        encrypted = encrypted + cipher_text
    return encrypted, key

def ecb_decrypt(key, ciphertext):
    cipher = AES.new(key,AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

def xor_byte(byte_str1, byte_str2):
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_str1, byte_str2)])

def cbc(data):
    key = os.urandom(16)
    cipher = AES.new(key,AES.MODE_ECB)
    cipher_list = []
    encrypted = b''

    first = xor_byte(data[0], key)
    cipher_list.append(first)

    for p in range(1, len(data)-1):
        xor = xor_byte(data[p], cipher_list[p-1])
        cipher_text = cipher.encrypt(xor)
        cipher_list.append(cipher_text)

    for en in cipher_list:
        encrypted = encrypted + en
    return encrypted, key

def cbc_decrypt(key, ciphertext):
    cipher = AES.new(key,AES.MODE_ECB)
    decrypt_list = []
    temp = []
    final = b''
    # decrypted = cipher.decrypt(ciphertext)
    block_text = create_blocks(ciphertext)
    decrypt = cipher.decrypt(block_text[0])
    temp.append(block_text[0])
    first = xor_byte(decrypt, key)
    decrypt_list.append(first)

    for p in range(1, len(block_text)-1):
        decrypt = cipher.decrypt(block_text[p])
        temp.append(block_text[p])
        xor = xor_byte(decrypt, temp[p-1])
        decrypt_list.append(xor)

    for d in decrypt_list:
        final = final + d
    
    return final

def writer(file_path,header ,encrypted_data):
    with open(file_path, 'wb') as bmp_file:
        bmp_file.write(header)   
        bmp_file.write(encrypted_data)       

main()