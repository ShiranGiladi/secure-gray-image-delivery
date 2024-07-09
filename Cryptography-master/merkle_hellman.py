import random
# from Crypto.Random import get_random_bytes

# Extended Euclidean Algorithm to find modular inverse
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# Generate superincreasing sequence
def generate_superincreasing_sequence(n):
    W = [random.randint(1, 100) for _ in range(n)]
    for i in range(1, n):
        W[i] += sum(W[:i])
    return W

# Generate keys
def generate_keys(n):
    W = generate_superincreasing_sequence(n)
    q = random.randint(sum(W) + 1, sum(W) * 2)
    r = random.randint(2, q - 1)
    while extended_gcd(r, q)[0] != 1:
        r = random.randint(2, q - 1)
    B = [(r * wi) % q for wi in W]
    return (W, q, r), B

# Encrypt
def encrypt(message, B):
    c = sum([m * bi for m, bi in zip(message, B)])
    return c

# Decrypt
def decrypt(c, private_key):
    W, q, r = private_key
    r_inv = modinv(r, q)
    c_prime = (c * r_inv) % q

    subset_sum = []
    current_sum = c_prime
    for wi in reversed(W):
        if wi <= current_sum:
            subset_sum.append(1)
            current_sum -= wi
        else:
            subset_sum.append(0)
    subset_sum.reverse()

    # Pad subset_sum with zeros to ensure it's a multiple of 8
    pad_len = (8 - len(subset_sum) % 8) % 8
    subset_sum += [0] * pad_len

    # Convert subset_sum to a list of bytes
    decrypted_bytes = bytes([int(''.join(map(str, subset_sum[i:i+8])), 2) for i in range(0, len(subset_sum), 8)])

    return decrypted_bytes

# =============================================================================
# # Example usage
# message = get_random_bytes(16)
# #message = b"\xfaj\xfc\xe4'\x1f\xde\n\xdb\x0c-Cf\x82\xcbM"
# print("R_Message:", message)
# message_bits = [int(bit) for byte in message for bit in f"{byte:08b}"]
# private_key, public_key = generate_keys(len(message_bits))
# ciphertext = encrypt(message_bits, public_key)
# decrypted_message = decrypt(ciphertext, private_key)
# print("D_Message:", decrypted_message)
# =============================================================================
