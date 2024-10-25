import Crypto.Cipher
import Crypto.Cipher.AES as AES
import random
from Crypto.Hash import SHA256
import os
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes

# Show that Mallory can recover the messages 𝑚0 and 𝑚1 from their ciphertexts by setting alpha to 1, q, or q-1.
# enerate_private_key
# compute_public_key # The pow() function allows you to calculate the power of a number and perform modular exponentiation.
# compute_shared_secret
# derive_key
# encrypt_message
# decrypt_message
# mitm_generator_attack


# X is private key
# Y is public key
# K is shared secret
# Mallory gets Alice's public key
def main():
    # Capability to use large 1024 bit numbers:
    #test_q = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
    #test_alpha = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
    nE, nD = generate_keypair(2048)
    test_q = str(nE[0])
    test_alpha = str(nD[1])
    print("TQ", test_q)
    print("\n",nD[1])
    print("\nTA", test_alpha)

    real_num_q, real_num_alpha = parse_real_numbers(test_q, test_alpha)
    # print(real_num_q, real_num_alpha)

    # Get private and public keys
    Alice_private, Alice_public, q = diffie_hellman_protocol(real_num_q, real_num_alpha)
    Bob_private, Bob_public, q = diffie_hellman_protocol(real_num_q, real_num_alpha)
    iv = os.urandom(16)

    # Mallory intercepts both the public keys
    Mallory_public_key_Alice = Alice_public
    Mallory_public_key_Bob = Bob_public

    # Mallory sends q to Bob and send q to Alice instead of public keys, this changes how the secret keys are calculated
    Bob_secret_key, Alice_secret_key, Mallory_secret_key = mitm_key_fixing_attack(
        q, Mallory_public_key_Bob, Bob_private, Alice_private
    )

    # Compute shared secret
    print("Alice:\n", Alice_secret_key)
    print("Bob\n", Bob_secret_key)
    print("Mallory\n", Mallory_secret_key)

    # Get encryption and decryption keys
    Alice_key = derive_key(Alice_secret_key)
    Bob_key = derive_key(Bob_secret_key)
    Mallory_key = derive_key(Mallory_secret_key)

    # Encrypt Alice's message. Bob Decrypts it
    ciphertext = encrypt_message(iv, "I hope no one can intercept this", Alice_key)
    decrypted = decrypt_message(iv, ciphertext, Mallory_key)

    print("MITM key attack: ", decrypted)

    # Separate function that is similar to main. Goes through the mitm attack where alpha is tampered with.
    mitm_generator_attack(real_num_q, real_num_alpha)
    return

def mod_inverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m
    
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y   
    
    
def generate_prime(bits):
    return getPrime(bits, randfunc=get_random_bytes)

def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Requirement: Use the value e=65537
    d = mod_inverse(e, phi)
    d_check = pow(e, -1, phi)
    #print(f"\nmod_inverse_check (d): {d}")
    #print(f"pow (d_check): {d_check}\n")
    return ((n, e), (n, d))

def generate_private_key():
    return random.randint(10, 1000)


def compute_public_key(q, alpha, private_key):
    return pow(alpha, private_key, q)


def compute_shared_secret(public_key, private_key, q):
    return pow(public_key, private_key, q)


def derive_key(shared_secret):
    shash = SHA256.new()
    shash.update(int.to_bytes(shared_secret))
    k = shash.digest()
    key = k[:16]
    return key


def encrypt_message(iv, message, key):
    byte_string = message.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(byte_string, 16))
    return ciphertext


def decrypt_message(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    return decrypted


def diffie_hellman_protocol(q, alpha):
    private_key = generate_private_key()
    public_key = compute_public_key(q, alpha, private_key)
    return private_key, public_key, q


def parse_real_numbers(q, alpha):
    q_int_string = int(q, 16)
    alpha_int_string = int(alpha, 16)
    return q_int_string, alpha_int_string


def mitm_key_fixing_attack(q, Mallory_public, Bob_private, Alice_private):
    Bob_secret_key = compute_shared_secret(q, Bob_private, q)
    Alice_secret_key = compute_shared_secret(q, Alice_private, q)
    Mallory_secret_key = compute_shared_secret(q, Mallory_public, q)
    return Bob_secret_key, Alice_secret_key, Mallory_secret_key


def mitm_generator_attack(q, alpha):
    # Mallory changes alpha to = q
    # do two iterations alpha = 1 and alpha = q - 1
    Alice_private, Alice_public, q = diffie_hellman_protocol(q, q)
    Bob_private, Bob_public, q = diffie_hellman_protocol(q, q)
    iv = os.urandom(16)

    # Mallory intercepts both the public keys
    Mallory_public_key_Alice = Alice_public
    Mallory_public_key_Bob = Bob_public

    # Mallory is able to calculate the secret key because Alpha was changed to alpha = q
    Alice_secret_key = compute_shared_secret(Bob_public, Alice_private, q)
    Bob_secret_key = compute_shared_secret(Alice_public, Bob_private, q)
    Mallory_secret_key = compute_shared_secret(
        Mallory_public_key_Bob, random.randint(10, 1000), q
    )

    # Compute shared secret
    # print("Alice:\n" , Alice_secret_key)
    # print("Bob\n", Bob_secret_key)
    # print("Mallory\n", Mallory_secret_key)

    # Get encryption and decryption keys
    Alice_key = derive_key(Alice_secret_key)
    Bob_key = derive_key(Bob_secret_key)
    Mallory_key = derive_key(Mallory_secret_key)

    # Encrypt Alice's message. Mallory Decrypts it
    ciphertext = encrypt_message(iv, "I hope no one can intercept this", Alice_key)
    decrypted = decrypt_message(iv, ciphertext, Mallory_key)

    print("MITM Generator attack: ", decrypted)
    return


main()
