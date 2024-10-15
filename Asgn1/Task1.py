# Andrew Okelund
import Crypto
import Crypto.Cipher
import Crypto.Cipher.AES as AES
import os

from Crypto.Util.Padding import pad

# Read in bmp file
# Pad bmp file if necessary
# Create blocks of 128 bits
Crypto.Cipher.AES


def main():
    file_path = "cp-logo.bmp"
    body, header = reader(file_path)
    blocks = create_blocks(body)

    # ECB FUNCTIONS
    ecb_key = os.urandom(16)
    ecb_encrypted = ecb(blocks, ecb_key)
    ecb_d = ecb_decrypt(ecb_key, ecb_encrypted)
    writer("cp-logo-ENcrypted-ECB.bmp", header, ecb_encrypted)
    writer("cp-logo-DEcrypted-ECB.bmp", header, ecb_d)

    # CBC FUNCTIONS
    cbc_key = os.urandom(16)
    cbc_iv = os.urandom(16)
    cbc_encrypted = cbc(blocks, cbc_key, cbc_iv)
    cbc_d = cbc_decrypt(cbc_key, cbc_encrypted, cbc_iv)
    writer("cp-logo-ENcrypted-CBC.bmp", header, cbc_encrypted)
    writer("cp-logo-DEcrypted-CBC.bmp", header, cbc_d)

    return


def reader(file_path):

    with open(file_path, "rb") as file:
        header = file.read(54)
        body = file.read()

    body_length = len(body)
    pad_test = body_length % 16

    if pad_test != 0:
        pad_length = 16 - pad_test
        padding = bytes([pad_length] * pad_length)
        padded_body = body + padding
        return padded_body, header
    return body, header


def create_blocks(body):
    blocks = [body[i : i + 16] for i in range(0, len(body), 16)]
    return blocks


def ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = b""
    for p in data:
        cipher_text = cipher.encrypt(p)
        encrypted = encrypted + cipher_text
    return encrypted


def ecb_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted


def xor_byte(byte_str1, byte_str2):
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_str1, byte_str2)])


def cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = b""
    previous_block = iv
    for block in data:
        xor = xor_byte(block, previous_block)
        cipher_text = cipher.encrypt(xor)
        encrypted += cipher_text
        previous_block = cipher_text
    return encrypted


def cbc_decrypt(key, ciphertext, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypt_list = []
    block_text = create_blocks(ciphertext)
    previous_block = iv 
    for block in block_text:
        decrypted = cipher.decrypt(block)
        xor = xor_byte(decrypted, previous_block)
        decrypt_list.append(xor)
        previous_block = block 

    final = b"".join(decrypt_list)
    return final


def writer(file_path, header, encrypted_data):
    with open(file_path, "wb") as bmp_file:
        bmp_file.write(header)
        bmp_file.write(encrypted_data)


main()