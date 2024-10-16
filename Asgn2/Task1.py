import Crypto
import Crypto.Cipher
import Crypto.Cipher.AES as AES
import random
from Crypto.Hash import SHA256
import os
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


#use some “real life” numbers. IETF suggestion
#generate_private_key
#compute_public_key # The pow() function allows you to calculate the power of a number and perform modular exponentiation.
#compute_shared_secret
#derive_key
#encrypt_message
#decrypt_message
#diffie_hellman_protocol

from Crypto.Util.Padding import pad

def main():
    # Diffie Hellman protocol, get public and private keys for Bob and Alice
    
    test_q = "23"
    #test_q = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
    test_alpha = "5"
    #test_alpha = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
    real_num_q, real_num_alpha = parse_real_numbers(test_q, test_alpha)
    print(real_num_q, real_num_alpha)
    Alice_private, Alice_public, q = diffie_hellman_protocol(real_num_q, real_num_alpha)
    Bob_private, Bob_public, q = diffie_hellman_protocol(real_num_q, real_num_alpha)
    iv =  os.urandom(16)

    # Compute shared secret
    Alice_secret_key = compute_shared_secret(Bob_public, Alice_private, q)
    Bob_secret_key = compute_shared_secret(Alice_public, Bob_private, q)

    print("Alice:\n" , Alice_secret_key)
    print("Bob\n", Bob_secret_key)
    
    # Get encryption and decryption keys
    Alice_key = derive_key(Alice_secret_key)
    Bob_key = derive_key(Bob_secret_key)
    
    # Encrypt Alice's message. Bob Decrypts it
    ciphertext_Alice = encrypt_message(iv, "I hope no one can intercept this", Alice_key)
    decrypted_Bob = decrypt_message(iv, ciphertext_Alice, Bob_key)
    print("Decrypted", decrypted_Bob)

    ciphertext_Bob = encrypt_message(iv, "No way Jose! We are safe", Bob_key)
    decrypted_Alice = decrypt_message(iv, ciphertext_Bob, Alice_key)
    print("Decrypted", decrypted_Alice)

def generate_private_key():
    return random.randint(10, 1000)

def compute_public_key(q, alpha, private_key):
    return pow(alpha, private_key, q)

def compute_shared_secret(public_key, private_key, q):
    return pow(public_key, private_key, q)

def derive_key(shared_secret):
    shash = SHA256.new() 
    shash.update( int(shared_secret).to_bytes(128, byteorder= 'big'))
    k = shash.digest()
    key = k[:16]
    return key

def encrypt_message(iv, message, key):
    byte_string = message.encode('utf-8')
    cipher = AES.new(key ,AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(byte_string, 16))
    return ciphertext

def decrypt_message(iv, ciphertext, key):
    cipher = AES.new(key ,AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16) 
    return decrypted

def diffie_hellman_protocol(q, alpha):
    # q = 23 #sympy.randprime(10**5, 10**6)
    # alpha = 5 #random.randint(1, 100000)
    private_key = generate_private_key()
    public_key = compute_public_key(q, alpha, private_key)
    return private_key, public_key, q

def parse_real_numbers(q, alpha):
    q_int_string = int(q, 16)
    alpha_int_string = int(alpha, 16)
    return q_int_string, alpha_int_string

main()
