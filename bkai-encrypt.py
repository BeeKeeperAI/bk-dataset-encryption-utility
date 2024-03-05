import os
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_file_path, key_path, output_file_path):
    """Encrypt a file using AES-256-GCM with PBKDF2 key derivation."""
    with open(key_path, 'rb') as key_file:
        password = key_file.read().rstrip()
    password = password if isinstance(password, (bytes, bytearray)) else password.encode()

    # Generate a random salt
    salt = os.urandom(8)

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32 + 12,  # 32 bytes for AES key and 12 for nonce
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password)
    key = derived_key[:32]
    nonce = derived_key[32:44]

    # Encrypt the file
    aesgcm = AESGCM(key)
    with open(input_file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Save the encrypted file with "Salted__" prefix, salt, and ciphertext
    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(b'Salted__' + salt + ciphertext)

def decrypt_file(input_file_path, key_path, output_file_path):
    """Decrypt a file using AES-256-GCM with PBKDF2 key derivation."""
    with open(input_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    # Check for the "Salted__" prefix
    if not encrypted_data.startswith(b'Salted__'):
        raise ValueError("Invalid encrypted file format or missing 'Salted__' prefix.")
    
    salt = encrypted_data[8:16]  # Extract salt
    ciphertext = encrypted_data[16:]  # The rest is the ciphertext
    
    with open(key_path, 'rb') as key_file:
        password = key_file.read().rstrip()
    password = password if isinstance(password, (bytes, bytearray)) else password.encode()

    # Derive key from password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32 + 12,  # 32 bytes for AES key and 12 for nonce
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password)
    key = derived_key[:32]
    nonce = derived_key[32:44]

    # Decrypt the file
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Save the decrypted content
    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using AES-256-GCM with PBKDF2 key derivation for BeeKeeperAI\'s EscrowAI Platform.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("--input", required=True, help="Input file path")
    parser.add_argument("--key", required=True, help="Key file path")
    parser.add_argument("--output", required=True, help="Output file path")

    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_file(args.input, args.key, args.output)
    elif args.action == "decrypt":
        decrypt_file(args.input, args.key, args.output)

if __name__ == "__main__":
    main()
