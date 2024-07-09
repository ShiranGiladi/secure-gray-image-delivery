from aria import aria_algorithm as aria
from merkle_hellman import generate_keys, encrypt, decrypt
from dsa import generate_params, generate_dsa_keys, sign, verify

from Crypto.Random import get_random_bytes

iv = b'initrandomvector'  # 16 bytes IV

def xor_bytes(data1, data2):
    """ XOR two bytes objects of equal length """
    return bytes(b1 ^ b2 for b1, b2 in zip(data1, data2))

def ofb_mode_encrypt(key, iv, plaintext):
    """
    Encrypts plaintext using the OFB (Output Feedback) mode with ARIA algorithm.

    :param key: The symmetric key.
    :param iv: The initialization vector.
    :param plaintext: The plaintext to encrypt.
    :return: The encrypted ciphertext.
    """
    output = bytearray()
    block = iv

    for i in range(0, len(plaintext), 16):
        # Encrypt the block using ARIA algorithm
        block = aria.ARIA_encryption(int.from_bytes(block, 'big'), int.from_bytes(key, 'big'), 128).to_bytes(16, 'big')

        # XOR the plaintext with the encrypted block
        block_size = min(len(plaintext) - i, 16)
        output.extend(xor_bytes(block, plaintext[i:i + block_size]))

    return bytes(output)

def ofb_mode_decrypt(key, iv, input_bytes):
    """
    Decrypts ciphertext using the OFB (Output Feedback) mode with ARIA algorithm.

    :param key: The symmetric key.
    :param iv: The initialization vector.
    :param input_bytes: The ciphertext to decrypt.
    :return: The decrypted plaintext.
    """
    output = bytearray()
    block = iv

    for i in range(0, len(input_bytes), 16):
        # Encrypt the block using ARIA algorithm
        block = aria.ARIA_encryption(int.from_bytes(block, 'big'), int.from_bytes(key, 'big'), 128).to_bytes(16, 'big')

        # XOR the input bytes with the encrypted block
        block_size = min(len(input_bytes) - i, 16)
        output.extend(xor_bytes(block, input_bytes[i:i + block_size]))

    return bytes(output)

def encrypt_gray_image(path, key):
    """
    Encrypts a grayscale image file using OFB mode with ARIA algorithm.

    :param path: The path to the grayscale image file.
    :param key: The symmetric key.
    :return: The encrypted image bytes.
    """
    # Print path of the image file
    print('The path of file: ', path)

    # Open the file for reading
    with open(path, 'rb') as fin:
        # Store image data in the variable "image"
        image = bytearray(fin.read())
    bytes=ofb_mode_encrypt(key,iv,image)
    
    return bytes
   
def decrypt_gray_image(image_bytes, output_path, key, iv):
    """
    Decrypts a grayscale image using OFB mode with ARIA algorithm.

    :param image_bytes: The encrypted image bytes.
    :param output_path: The path where the decrypted image will be saved.
    :param key: The symmetric key.
    :param iv: The initialization vector.
    """
    # Decrypt the image bytes using OFB mode
    decrypted_bytes = ofb_mode_decrypt(key, iv, image_bytes)

    # Write the decrypted bytes to the output file
    with open(output_path, 'wb') as fout:
        fout.write(decrypted_bytes)

    print(f'\nDecryption complete. Image saved to: {output_path}')

def write_string_to_file(string_data, file_path):
    """
    Write a given string to a text file.

    :param string_data: The string to write to the file.
    :param file_path: The path of the file where the string will be written.
    """
    with open(file_path, 'wb') as file:
        file.write(string_data)


# Alice want to send an image to Bob

# Alice: encryption part - encrypt ARIA key, encrypt the image, signature

# Alice generates ARIA key
aria_key = get_random_bytes(16)
aria_key_bits = [int(bit) for byte in aria_key for bit in f"{byte:08b}"]

# Bob generate Merkle–Hellman knapsack keys
private_key, public_key = generate_keys(len(aria_key_bits))

# Alice encrypts the ARIA secret key with Bob's public key
encrypted_aria_key = encrypt(aria_key_bits, public_key)

# Alice encrypts the image using the ARIA key 
encrypted_image = encrypt_gray_image('cat.png', aria_key)
write_string_to_file(encrypted_image,"encrypted_image.txt")

# Signature part
# Generate keys and parameters
L, N = 1024, 160
# Public parameters
p, q, g = generate_params(L, N)

# x - Alice's private key, y - Alice's public key
x, y = generate_dsa_keys(g, p, q)

# Alice signs the encrypted image
r, s = sign(encrypted_image, p, q, g, x)

# Alice sends the signature (r, s), along with the public key y, to Bob
# Alice sends the encrypted ARIA secret key and the encrypted image to Bob

# Bob: decryption part - decrypt ARIA key, decrypt the image, verify the signature

# Bob decrypts the ARIA secret key using his private key
decrypted_aria_key = decrypt(encrypted_aria_key, private_key)

# Bob receives the encrypted image from Alice
# Bob decrypts the image using the decrypted ARIA key  
decrypted_image = decrypt_gray_image(encrypted_image, "output.png", decrypted_aria_key, iv)

# Bob receives the encrypted_image, r, s, and y
# Verify the signature using Bob's side
is_valid = verify(encrypted_image, r, s, p, q, g, y)
if is_valid:
    print("\nSignature is valid. Image is from Alice.")
else:
    print("\nSignature is not valid. Image may be tampered or from an unauthorized source.")

# print("\naria_key:", aria_key)
# print("\ndecrypted_aria_key:", decrypted_aria_key)
