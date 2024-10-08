# CS-445-Model
This is a model created for CS 445. This model combines features from both ChaCha20 and Serpent.

## Requirements
- Python
- The `Lorem` library for plaintext generation. You can install it via:

```
pip install lorem
```

## Usage
1. CD into New_Model folder
2. Prepare the plaintext.txt file with the text u want to encrypt/decrypt
3. Execute the script with:
```
python model2.py
```
3. Analyze outputs
- ciphertext_combined.txt: Contains the encrypted data
- decrypted_combined.txt: Contains the decrypted plaintext
- The Console also provides block cipher text for each block and the final cipher text once stream cipher is done 

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
