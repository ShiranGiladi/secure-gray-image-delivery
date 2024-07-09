# Secure Gray Image Delivery
An application for secure delivery of gray images, implementing encryption-decryption using ARIA in OFB mode, secret key delivery via Merkle–Hellman knapsack, and authentication using DSA signatures.

## ARIA Algorithm

**Introduction to ARIA:**
ARIA (Advanced Encryption Standard (AES) Replacement) is a symmetric block cipher designed for high security and efficiency.

**Key Features:**
- Block Size: 128 bits
- Key Size: 128 bits
- Number of Rounds: 12

**Encryption Process:**
1. **Key Expansion:** Generates four 128-bit values (W0, W1, W2, W3) from the master key using a 3-round 256-bit Feistel cipher.
2. **Encryption Rounds:** Each round includes round key addition, substitution layer, and diffusion layer.
3. **Final Round:** Substitutes the diffusion layer with the round key addition step.

**Decryption Process:**
Similar to encryption but with round keys used in reverse order.

## OFB Mode for Secure Data Transmission

**Operation:**
- Initialization Vector (IV) of block cipher's block size.
- Encrypts IV to produce a keystream used for XORing with plaintext to produce ciphertext.

**Advantages:**
- Error Propagation: Errors in ciphertext do not affect subsequent blocks.
- Security Considerations: Requires unique IV for each encryption operation.

## Secret Key Delivery using Merkle–Hellman Knapsack

**Key Components:**
- Superincreasing Sequence: Sequence ensuring each element is larger than the sum of all preceding elements.
- Private Key: Consists of superincreasing sequence (W), prime number (q), and r.
- Public Key: Generated from the superincreasing sequence and r for encryption.

**Encryption Process:**
- Converts symmetric key to binary.
- Multiplies each bit with corresponding element of public key to generate ciphertext.

**Decryption Process:**
- Uses private key superincreasing sequence to invert encryption process and recover plaintext.

## Digital Signature Algorithm (DSA)

**Signature Generation Process:**
1. **Message Hashing:** Hashes message using cryptographic hash function.
2. **Random Number Generation:** Generates secret random number (k).
3. **Calculation of r and s:** Computes signature components using modular arithmetic.
4. **Output:** Signature represented as (r, s).

**Signature Verification Process:**
1. **Message Hashing:** Hashes received message.
2. **Decomposition of Signature:** Decomposes received signature into components.
3. **Calculations:** Verifies authenticity of signature using sender's public key.

## Component Integration

**ARIA Encryption:**
Ensures confidentiality during transmission using robust cryptographic algorithms.

**Merkle–Hellman Key Delivery:**
Securely distributes encryption keys to authorized recipients.

**DSA Signature:**
Provides proof of sender's identity and ensures data integrity.

## Workflow

1. **Data Encryption:**
   - Encrypts gray image using ARIA encryption with symmetric key.

2. **Key Generation and Distribution:**
   - Receiver generates public key for symmetric key encryption using Merkle–Hellman.
   - Securely delivers public key to sender.

3. **Signature Generation:**
   - Sender generates digital signature using DSA to authenticate data.

4. **Transmission:**
   - Sends encrypted data and digital signature to receiver.

5. **Verification and Decryption:**
   - Receiver verifies signature using sender's public key.
   - If valid, decrypts symmetric key using Merkle–Hellman private key.
   - Decrypts data using symmetric key.
