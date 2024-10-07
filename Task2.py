import Task1
import Crypto.Cipher.AES as AES
from Crypto.Util.Padding import pad
import urllib.parse
from Crypto.Util.Padding import unpad
import os


def main():
    key = os.urandom(16)
    iv = os.urandom(16)

    user_input = "You're the man now, dog;admin=true;"

    ciphertext = submit(user_input, key, iv)
    print(ciphertext)

    tampered_ciphertext = tamper_ciphertext(ciphertext)
    print("tampered", tampered_ciphertext, len(tampered_ciphertext))
    

    is_admin_tamp = verify(tampered_ciphertext, key, iv)
    is_admin_valid = verify(ciphertext, key, iv)

    print("Admin Access Before Tamper:", is_admin_valid)
    print("Admin Access After Tamper:", is_admin_tamp)


def submit(userdata, key, iv):
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    full_string = prefix + urllib.parse.quote(userdata) + suffix
    full_data = full_string.encode('ascii')
    pad_test = len(full_data) % 16
    if pad_test % 16 != 0:
        full_data = full_data + bytes([16 - pad_test] * (16 - pad_test))
    blocks = Task1.create_blocks(full_data)
    ciphertext = Task1.cbc(blocks, key, iv)
    return ciphertext



def verify(ciphertext, key, iv):
    decrypted_data = Task1.cbc_decrypt(key, ciphertext, iv)
    print(decrypted_data)
    try:
        unpadded_data = unpad(decrypted_data, AES.block_size)
    except ValueError:
        print("err")
        return False
    decoded_data =  unpadded_data.decode('ascii')
    user_data = urllib.parse.unquote(decoded_data)
    print("Decrypted Data:", user_data)
    return ";admin=true;" in decoded_data


# def tamper_ciphertext(ciphertext):
#     # Target string to inject
#     injection = ";admin=true;"
#     injection_bytes = injection.encode('ascii')
    
#     out = b""

#     blocks = Task1.create_blocks(ciphertext)
#     out += blocks[0]
#     blocks[1] = blocks[1][:4] + injection_bytes
#     prev = Task1.xor_byte(blocks[0], blocks[1])
#     out += prev 
#     for i in blocks[2:]:
#         xor = Task1.xor_byte(i, prev)
#         out += xor
#         prev = xor
#     return out

def tamper_ciphertext(ciphertext):
    # Convert ciphertext to mutable bytearray
    enc_list = bytearray(ciphertext)

    # Modify specific bytes using XOR operations
    enc_list[4] ^= (ord("@") ^ ord(";"))  # Modify the 5th byte
    enc_list[10] ^= (ord("$") ^ ord("="))  # Modify the 11th byte
    enc_list[15] ^= (ord("*") ^ ord(";"))  # Modify the 16th byte

    print( enc_list)
    return bytes(enc_list)

if __name__ == "__main__":
    main()
