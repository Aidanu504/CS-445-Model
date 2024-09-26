# CS-445-Model
This is a model created for CS 445. This model combines features from both ChaCha20 and Serpent.

## Requirements
- Python
- The `colorama` library for colored console output. You can install it via:

```
pip install colorama
```

## Usage
1. Prepare the input.txt file with the text u want to encrypt/decrypt
2. Execute the script with:
```
python model.py
```
3. Analyze outputs
- encrypted.bin: Contains the encrypted data
- decrypted.txt: Contains the decrypted plaintext
- The Console also provides stream and block cipher text

## Model details
This model combines features from both ChaCha20 and Serpent.
Below is the paramaters for each component of ChaCha20 and serpent in the model.

| Cipher Type | Key Size              | Block Size           | Rounds            |
|-------------|-----------------------|----------------------|-------------------|
| ChaCha20    | 256 bits (32 bytes)   | 64 bytes (512 bits)  | 20 rounds         |
| Serpent     | 256 bits (32 bytes)   | 16 bytes (128 bits)  | 32 rounds         |

## Components
| Component             | Description                                      |
|-----------------------|--------------------------------------------------|
| **Input Layer**       | Plaintext input from a file                      |
| **Key Generation**    | 256-bit key for Serpent; 8-byte nonce           |
| **ChaCha20**          | Stream cipher for keystream generation           |
| **Serpent**           | Block cipher for encrypting 128-bit blocks      |
| **Hybrid Encryption**  | Combines both ciphers to encrypt plaintext       |
| **Decryption**        | Reverses the encryption process using the same keys and nonce |
