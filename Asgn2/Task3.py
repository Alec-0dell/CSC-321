import random
from Crypto.Util import number

def main():
    # print out c and s prime for the grader
    # sign the message and show that i can forge the digital signature
    
    
    # RSA Key Generation (for Alice)
    bits = 512  # Reduced size for demonstration; you can use up to 2048 bits.
    public_key, private_key = generate_keypair(bits)

    # Alice encrypts a message
    message = "Hi Bob this is a secret!"
    m = string_to_int(message)  # Convert message to integer
    print(f"Alice's original message (as integer): {m}")
    
    # Alice computes c = m^e mod n (encrypted message)
    c = encrypt(public_key, m)
    print(f"Alice's ciphertext: {c}")

    # Mallory performs a malleability attack by modifying the ciphertext
    factor = random.randint(2, public_key[0] - 1)
    c_prime = mitm_attack(public_key, c, factor)
    print(f"\nMallory's modified ciphertext: {c_prime}")

    # Bob decrypts Mallory's modified ciphertext (thinking it came from Alice)
    s_prime = decrypt(private_key, c_prime)
    print("\nc_prime", c_prime, "\ns_prime", s_prime)
    print(f"Bob's decrypted value (s'): {s_prime}")

    # Mallory recovers the original message by reversing the attack
    s_mallory = mallory_recover_secret(s_prime, factor, public_key[0])
    print(f"\nMallory's recovered value (original message as integer): {s_mallory}")

    # Mallory converts the integer back to the original message
    recovered_message = int_to_string(s_mallory)
    print(f"Mallory's recovered message: {recovered_message}")
    
    
     # Alice signs two messages
    mes1 = "Hi Bob this is a signed message!"
    mes2 = "Hi Bob this is another message that I have signed!"
    m1 = string_to_int(mes1)  # Convert message1 to integer
    m2 = string_to_int(mes2)  # Convert message2 to integer

    print(f"\nAlice's original message1 (as integer): {m1}")
    print(f"Alice's original message2 (as integer): {m2}")

    # Alice creates digital signatures for both messages
    s1 = sign(private_key, m1)
    s2 = sign(private_key, m2)

    print(f"\nAlice's 1st digital signature: {s1}")
    print(f"Alice's 2nd digital signature: {s2}")

    # Bob verifies both signatures
    is1_valid = verify(public_key, m1, s1)
    is2_valid = verify(public_key, m2, s2)
    print(f"\nIs the 1st signature valid? {is1_valid}")
    print(f"Is the 2nd signature valid? {is2_valid}")

    # Mallory creates a forged message and signature
    m3 = (m1 * m2) % public_key[0]  # n is public_key[0]
    s3 = (s1 * s2) % public_key[0]  # Signature forged using multiplication

    print(f"\nMallory's forged message (m3 = m1 * m2 mod n): {m3}")
    print(f"Mallory's forged signature for m3: {s3}")

    # Verify the forged signature
    is_forged_valid = verify(public_key, m3, s3)
    print(f"\nIs the forged signature valid? {is_forged_valid}")
    
def generate_prime(bits):
    return number.getPrime(bits)

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, y = egcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

# RSA Key Generation
def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  
    d = mod_inverse(e, phi) 
    return ((n, e), (n, d))  

# RSA Encryption
def encrypt(public_key, message):
    n, e = public_key
    return pow(message, e, n)

# RSA Decryption
def decrypt(private_key, ciphertext):
    n, d = private_key
    return pow(ciphertext, d, n)

def string_to_int(message):
    hex_string = message.encode().hex()
    return int(hex_string, 16)

def int_to_string(number):
    hex_string = hex(number)[2:]
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return bytes.fromhex(hex_string).decode()

# MITM attack
def mitm_attack(public_key, ciphertext, factor):
    n, e = public_key
    return (ciphertext * pow(factor, e, n)) % n

# Mallory recovers the original secret
def mallory_recover_secret(s_prime, factor, n):
    factor_inv = mod_inverse(factor, n)
    return (s_prime * factor_inv) % n

# RSA signing
def sign(private_key, message):
    n, d = private_key
    return pow(message, d, n)

# Verify an RSA signature.
def verify(public_key, message, signature):
    n, e = public_key
    return pow(signature, e, n) == message


main()