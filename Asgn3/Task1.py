import hashlib
import random
import string
import time
import matplotlib.pyplot as plot


def main():
    # A) Hash arbitrary input
    message = "Test String!"
    print(f"Input: {message}")
    print(f"SHA256 Hash: {sha256_hash(message)}")

    # B) Hash two strings with 1-bit difference
    message1 = "Hello"
    message2 = modify_bit(message1, 7)
    print(f"Message 1: {message1} | Hash: {sha256_hash(message1)}")
    print(f"Message 2: {message2} | Hash: {sha256_hash(message2)}")

    # C) Weak collision search
    target = "Testing"
    bits = 12
    collision_message, attempts = weak_collision_search(target, bits)
    print(f"Found collision in {attempts} attempts!")
    print(f"Original: {target} | Collision: {collision_message}")

    # Measure collisions
    bit_sizes, attempts_list, time_list = measure_collisions()

    # Plot results
    plot_figure(bit_sizes, time_list, 'Digest Size (bits)', 'Collision Time (seconds)', 'Digest Size vs Collision Time')
    plot_figure(bit_sizes, attempts_list, 'Digest Size (bits)', 'Number of Inputs', 'Digest Size vs Number of Inputs')


def sha256_hash(input_string):
    hash_object = hashlib.sha256(input_string.encode("utf-8"))
    return hash_object.hexdigest()


def modify_bit(input_string, bit_index):
    binary = bytearray(input_string.encode("utf-8"))
    byte_index, bit_position = divmod(bit_index, 8)
    binary[byte_index] ^= 1 << bit_position
    return binary.decode("utf-8", errors="ignore")


def truncated_sha256(input_string, bits):
    full_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    binary_hash = bin(int(full_hash, 16))[2:].zfill(256)
    return binary_hash[:bits]


def random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def weak_collision_search(target_message, bits, max_attempts=100000):
    target_hash = truncated_sha256(target_message, bits)
    attempts = 0

    while attempts < max_attempts:
        candidate = random_string()
        attempts += 1
        if candidate != target_message and truncated_sha256(candidate, bits) == target_hash:
            return candidate, attempts

    raise ValueError(f"No collision found in {max_attempts} attempts.")


def measure_collisions():
    bit_sizes = list(range(8, 51, 2))
    attempts_list = []
    time_list = []

    for bits in bit_sizes:
        target_message = random_string()
        target_hash = truncated_sha256(target_message, bits)
        attempts = 0
        start_time = time.time()

        while attempts < 100000:  # Avoid infinite loops
            candidate_message = random_string()
            attempts += 1
            if candidate_message != target_message and truncated_sha256(candidate_message, bits) == target_hash:
                break

        elapsed_time = time.time() - start_time
        attempts_list.append(attempts)
        time_list.append(elapsed_time)

    return bit_sizes, attempts_list, time_list


def plot_figure(x, y, xlabel, ylabel, title):
    plot.figure()
    plot.plot(x, y, marker='o')
    plot.xlabel(xlabel)
    plot.ylabel(ylabel)
    plot.title(title)
    plot.grid(True)
    plot.show()

main()
