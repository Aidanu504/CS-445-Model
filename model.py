import os
import struct
from colorama import Fore, Style
from typing import Tuple

BLOCK_SIZE = 16
SERPENT_NUM_ROUNDS = 32
CHUNK_SIZE = 4096
CHACHA20_BLOCK_SIZE = 64

# very simple chahca20 implementation using block size of 64
def chacha20_key_schedule(key: bytes, nonce: bytes, counter: int) -> bytes:
    state = bytearray(key) + nonce + struct.pack('<I', counter) + b'\x00' * 8
    return state[:CHACHA20_BLOCK_SIZE]

# Key scheduling for Serpent
def serpent_key_schedule(key: bytes) -> list[int]:
    assert len(key) in {16, 24, 32}, "Key must be 128, 192, or 256 bits"
    round_keys = [int.from_bytes(key[i:i + 4], 'little') for i in range(0, len(key), 4)]
    return round_keys + [0] * (SERPENT_NUM_ROUNDS - len(round_keys))

# simple Serpent round function 
def serpent_round_function(state: list[int], round_key: int) -> list[int]:
    new_state = [(word ^ round_key) for word in state]
    return new_state

# encrypts block using Serpent
def serpent_block_encrypt(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == BLOCK_SIZE, "Plaintext must be a single block"
    state = list(struct.unpack('<4I', plaintext))
    round_keys = serpent_key_schedule(key)

    for i in range(SERPENT_NUM_ROUNDS):
        state = serpent_round_function(state, round_keys[i])

    return struct.pack('<4I', *state)

# Generate ChaCha20 keystream
def generate_chacha_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    keystream = b''
    counter = 0

    while len(keystream) < length:
        keystream_block = chacha20_key_schedule(key, nonce, counter)
        keystream += keystream_block
        counter += 1

    return keystream[:length]

# Encrypt using both stream and block ciphers
def hybrid_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    padded_length = (len(plaintext) + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE
    padded_plaintext = plaintext.ljust(padded_length, b'\x00')
    keystream = generate_chacha_keystream(key, nonce, len(padded_plaintext))

    block_ciphertext = bytearray()
    stream_ciphertext = bytearray()

    for i in range(0, len(padded_plaintext), BLOCK_SIZE):
        block = padded_plaintext[i:i + BLOCK_SIZE]
        serpent_ciphertext = serpent_block_encrypt(block, key)
        cipher_block = bytes([b ^ k for b, k in zip(serpent_ciphertext, keystream[i:i + BLOCK_SIZE])])
        block_ciphertext.extend(cipher_block)
        stream_ciphertext.extend(keystream[i:i + BLOCK_SIZE])

    return bytes(stream_ciphertext), bytes(block_ciphertext)

# Decryption 
def hybrid_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    keystream = generate_chacha_keystream(key, nonce, len(ciphertext))
    
    decrypted_blocks = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        serpent_ciphertext = bytes([b ^ k for b, k in zip(block, keystream[i:i + BLOCK_SIZE])])
        decrypted_block = serpent_block_encrypt(serpent_ciphertext, key)
        decrypted_blocks.extend(decrypted_block)

    return decrypted_blocks.rstrip(b'\x00')

# function to format results 
def display_results(plaintext, stream_ciphertext, block_ciphertext, decrypted_text):
    print(Fore.CYAN + "=== Results ===" + Style.RESET_ALL)
    print(f"{Fore.YELLOW}Plaintext: {Style.RESET_ALL}{plaintext.decode('utf-8')}")
    print(f"{Fore.YELLOW}Stream Ciphertext: {Style.RESET_ALL}{stream_ciphertext.hex()}")
    print(f"{Fore.YELLOW}Block Ciphertext: {Style.RESET_ALL}{block_ciphertext.hex()}")
    print(f"{Fore.YELLOW}Decrypted Plaintext: {Style.RESET_ALL}{decrypted_text.decode('utf-8')}")

    if plaintext == decrypted_text:
        print(f"{Fore.GREEN}Decryption Check: The encryption and decryption worked.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Decryption Check: The encryption adn decryption failed.{Style.RESET_ALL}")

if __name__ == "__main__":
    key = b"1234567890abcdef1234567890abcdef" # key for serpent 
    nonce = os.urandom(8) # random
    input_file = 'input.txt'
    encrypted_file = 'encrypted.bin'
    decrypted_file = 'decrypted.txt'

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    stream_ciphertext, block_ciphertext = hybrid_encrypt(plaintext, key, nonce)

    with open(encrypted_file, 'wb') as out_f:
        out_f.write(block_ciphertext)

    decrypted_text = hybrid_decrypt(block_ciphertext, key, nonce)

    with open(decrypted_file, 'wb') as out_f:
        out_f.write(decrypted_text)

    display_results(plaintext, stream_ciphertext, block_ciphertext, decrypted_text)
