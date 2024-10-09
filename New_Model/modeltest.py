import os
from faker import Faker
import time  # Importing the time module

fake = Faker()

# Function to generate faker text and write to a file
def generate_faker(filename, num_paragraphs):
    with open(filename, 'w') as f:
        for _ in range(num_paragraphs):
            f.write(fake.paragraph() + '\n')

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
def stream_cipher(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Combined encryption function
def encrypt_combined(input_file, output_file, block_key, stream_key, rounds):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        original_text = f_in.read()
        
        # Start timing encryption
        start_time = time.time()

        # Block Cipher Encryption
        round_keys = generate_round_keys(block_key, rounds)
        encrypted_blocks = bytearray()
        
        for i in range(0, len(original_text), 16): 
            block = list(original_text[i:i + 16]) + [0] * (16 - (len(original_text[i:i + 16]))) 
            encrypted_block = encrypt_block(block, round_keys, rounds)
            encrypted_blocks.extend(bytes(encrypted_block))

        # Stream Cipher Encryption
        final_encrypted_data = stream_cipher(encrypted_blocks, stream_key)
        f_out.write(final_encrypted_data)

        # End timing encryption
        end_time = time.time()
        encryption_time = end_time - start_time
        return encryption_time  # Return the time taken

# Combined decryption function
def decrypt_combined(input_file, output_file, block_key, stream_key, rounds):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        encrypted_data = f_in.read()

        # Start timing decryption
        start_time = time.time()

        # Stream Cipher Decryption
        decrypted_data = stream_cipher(encrypted_data, stream_key)

        # Block Cipher Decryption
        round_keys = generate_round_keys(block_key, rounds)
        decrypted_blocks = bytearray()
        
        for i in range(0, len(decrypted_data), 16):  
            block = list(decrypted_data[i:i + 16])
            decrypted_block = decrypt_block(block, round_keys, rounds)
            decrypted_blocks.extend(bytes(decrypted_block).rstrip(b'\x00'))  
        
        f_out.write(decrypted_blocks)

        # End timing decryption
        end_time = time.time()
        decryption_time = end_time - start_time
        return decryption_time  # Return the time taken

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
    block_key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]  # Example 128-bit key for block cipher
    stream_key = [0x9A, 0xBC, 0xDE, 0xF0]  
    rounds = 16  

    encryption_times = []
    decryption_times = []

    # Test with different sets of data
    for num_paragraphs in range(1, 11):  # Generate files with 1 to 10 paragraphs
        input_file = f'plaintext_{num_paragraphs}.txt'
        generate_faker(input_file, num_paragraphs)  # Generate the faker data

        # Encrypt and measure time
        cipher_file = f'ciphertext_combined_{num_paragraphs}.txt'
        encryption_time = encrypt_combined(input_file, cipher_file, block_key, stream_key, rounds)
        encryption_times.append(encryption_time)

        # Decrypt and measure time
        decrypted_file = f'decrypted_combined_{num_paragraphs}.txt'
        decryption_time = decrypt_combined(cipher_file, decrypted_file, block_key, stream_key, rounds)
        decryption_times.append(decryption_time)

        # Verify that decryption matches the original plaintext
        verify_files(input_file, decrypted_file)

    # Calculate average times
    average_encryption_time = sum(encryption_times) / len(encryption_times)
    average_decryption_time = sum(decryption_times) / len(decryption_times)

    print(f"Average Encryption Time for 1 to 10 paragraphs: {average_encryption_time:.6f} seconds")
    print(f"Average Decryption Time for 1 to 10 paragraphs: {average_decryption_time:.6f} seconds")
