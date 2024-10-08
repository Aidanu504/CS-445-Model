import os
from faker import Faker

fake = Faker()

# Function to generate faker text and write to a file
def generate_faker(filename, num_paragraphs):
    with open(filename, 'w') as f:
        for _ in range(num_paragraphs):
            f.write(fake.paragraph())

# encyrption s box
# Very simple implementation
def s_box_substitution(block):
    substituted_block = [((x + 1) % 256) for x in block]  
    return substituted_block

# decryption s box
# Very simple implementation
def inverse_s_box_substitution(block):
    inverse_substituted_block = [((x - 1) % 256) for x in block] 
    return inverse_substituted_block

# Key Schedule Generation
def generate_round_keys(key, rounds):
    round_keys = []
    for i in range(rounds):
        round_key = [(x + i) % 256 for x in key]  
        round_keys.append(round_key)
    return round_keys

# Rotate bits to the left Encryption 
def rotate_left(block, bits):
    rotated_block = [(x << bits | x >> (8 - bits)) & 0xFF for x in block] 
    return rotated_block

# Rotate bits to the right for decryption 
def rotate_right(block, bits):
    rotated_block = [(x >> bits | x << (8 - bits)) & 0xFF for x in block]
    return rotated_block

# Block encryption function
def encrypt_block(block, round_keys, rounds):
    for round_num in range(rounds):
        block = s_box_substitution(block)
        block = rotate_left(block, round_num % 8)  
        block = [(x + round_keys[round_num][i]) % 256 for i, x in enumerate(block)]  
    return block

# Block decryption function
def decrypt_block(block, round_keys, rounds):
    for round_num in range(rounds - 1, -1, -1):
        block = [(x - round_keys[round_num][i]) % 256 for i, x in enumerate(block)]  
        block = rotate_right(block, round_num % 8)  
        block = inverse_s_box_substitution(block)
    return block

# Stream cipher encryption 
# simple XOR with a key
def stream_cipher_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Stream cipher decryption 
# same as encryption for XOR
def stream_cipher_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Combined encryption function
def encrypt_combined(input_file, output_file, block_key, stream_key, rounds):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        original_text = f_in.read()
        print(f"Original Text: {original_text}")

        # Block Cipher Encryption
        round_keys = generate_round_keys(block_key, rounds)
        encrypted_blocks = bytearray()
        
        for i in range(0, len(original_text), 16): 
            block = list(original_text[i:i + 16]) + [0] * (16 - (len(original_text[i:i + 16]))) 
            encrypted_block = encrypt_block(block, round_keys, rounds)
            encrypted_blocks.extend(bytes(encrypted_block))
            print(f"Block Cipher Text: {''.join(f'{x:02x}' for x in encrypted_block)}")

        # Stream Cipher Encryption
        final_encrypted_data = stream_cipher_encrypt(encrypted_blocks, stream_key)
        f_out.write(final_encrypted_data)
        print(f"Cipher Text (Combined): {''.join(f'{x:02x}' for x in final_encrypted_data)}")  

# Combined decryption function
def decrypt_combined(input_file, output_file, block_key, stream_key, rounds):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        encrypted_data = f_in.read()

        # Stream Cipher Decryption
        decrypted_data = stream_cipher_decrypt(encrypted_data, stream_key)

        # Block Cipher Decryption
        round_keys = generate_round_keys(block_key, rounds)
        decrypted_blocks = bytearray()
        
        for i in range(0, len(decrypted_data), 16):  
            block = list(decrypted_data[i:i + 16])
            decrypted_block = decrypt_block(block, round_keys, rounds)
            decrypted_blocks.extend(bytes(decrypted_block).rstrip(b'\x00'))  
        
        f_out.write(decrypted_blocks)
        print(f"Decrypted Text: {decrypted_blocks.decode(errors='ignore')}")  

# Verification
def verify_files(plaintext_file, decrypted_file):
    with open(plaintext_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
        plaintext = f1.read()
        decrypted_text = f2.read()
        if plaintext == decrypted_text:
            print("Success - The decrypted text matches the original plaintext")
        else:
            print("Fail - The decrypted text does NOT match the original plaintext")

if __name__ == "__main__":
    generate_faker('plaintext.txt', num_paragraphs=3)

    block_key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]  # Example 128-bit key for block cipher
    stream_key = [0x9A, 0xBC, 0xDE, 0xF0]  
    rounds = 16  

    encrypt_combined('plaintext.txt', 'ciphertext_combined.txt', block_key, stream_key, rounds)
    decrypt_combined('ciphertext_combined.txt', 'decrypted_combined.txt', block_key, stream_key, rounds)

    verify_files('plaintext.txt', 'decrypted_combined.txt')
