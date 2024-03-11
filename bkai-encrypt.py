# Copyright (c) 2024 BeeKeeperAI, Inc.
#
# Use of this source code is governed by an MIT
# license that can be found in the LICENSE.txt file 
# or at https://opensource.org/license/mit.

import os
import argparse
from pathlib import Path
import shutil
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import zipfile

# Set to True to enable debug mode or use debug argument
DEBUG_MODE = False

def debug_print(*args, **kwargs):
    if DEBUG_MODE:
        print(*args, **kwargs)

def zip_content(input_path, zip_file_name):
    """Zip the encrypted content, either a single file or a folder, and then remove the original content."""
    zip_file_path = f"{zip_file_name}"
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        if input_path.is_dir():
            for root, dirs, files in os.walk(input_path):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(input_path)
                    zipf.write(file_path, arcname)
        else:
            zipf.write(input_path, input_path.name)

    # Remove the original content after zipping
    if input_path.is_dir():
        debug_print(f"Removing folder: {input_path}")
        shutil.rmtree(input_path)
    else:
        debug_print(f"Removing file: {input_path}")
        os.remove(input_path)
    
    print(f"Content zipped as: {zip_file_path}")

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
        debug_print(f"Encrypting file: {input_file_path} to {output_file_path} with key from {key_path}")
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
        debug_print(f"Decrypting file: {input_file_path} to {output_file_path} with key from {key_path}")
        decrypted_file.write(plaintext)

def encrypt_folder(input_folder_path, key_path, output_folder_path):
    """Encrypt all files in a folder, maintaining the folder structure."""
    input_folder_path = Path(input_folder_path)
    output_folder_path = Path(output_folder_path)

    for file_path in input_folder_path.rglob('*'):
        if file_path.is_file():
            rel_path = file_path.relative_to(input_folder_path)
            dest_file_path = output_folder_path / rel_path.with_suffix(rel_path.suffix + '.bkenc')
            dest_file_path.parent.mkdir(parents=True, exist_ok=True)
            encrypt_file(str(file_path), key_path, str(dest_file_path))

def decrypt_folder(input_folder_path, key_path, output_folder_path):
    """Decrypt all files in a folder, maintaining the folder structure."""
    input_folder_path = Path(input_folder_path)
    output_folder_path = Path(output_folder_path)

    for file_path in input_folder_path.rglob('*'):
        if file_path.is_file() and file_path.suffix == '.bkenc':
            rel_path = file_path.relative_to(input_folder_path)
            # Remove the custom '.bkenc' extension
            orig_extension = rel_path.suffixes[-2] if len(rel_path.suffixes) > 1 else ''
            new_rel_path = rel_path.with_suffix(orig_extension)
            dest_file_path = output_folder_path / new_rel_path
            dest_file_path.parent.mkdir(parents=True, exist_ok=True)
            decrypt_file(str(file_path), key_path, str(dest_file_path))

def main():
    global DEBUG_MODE  # Declare DEBUG_MODE as global to modify the global instance
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file or folder using AES-256-GCM with PBKDF2 key derivation, with an option to zip the encrypted content.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("--input", required=True, help="Input file or folder path")
    parser.add_argument("--key", required=True, help="Content Encryption Key file path")
    parser.add_argument("--output", required=True, help="Output file or folder path")
    parser.add_argument("--zip", nargs='?', help="Optional. Provide a zip file name to zip the output. Requires a file name.")
    parser.add_argument("--debug", action='store_true', help="Enable debug mode for verbose output.")

    args = parser.parse_args()

    DEBUG_MODE = args.debug

    input_path = Path(args.input)
    output_path = Path(args.output)

    if args.action == "encrypt":
        if input_path.is_dir():
            output_path.mkdir(parents=True, exist_ok=True)
            encrypt_folder(input_path, args.key, output_path)
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            encrypt_file(input_path, args.key, output_path)
        
        if args.zip:
            zip_file_name = args.zip  # The zip file name is directly obtained from --zip
            zip_content(output_path, zip_file_name)

    elif args.action == "decrypt":
        if input_path.is_dir():
            output_path.mkdir(parents=True, exist_ok=True)
            decrypt_folder(input_path, args.key, output_path)
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            decrypt_file(input_path, args.key, output_path)

if __name__ == "__main__":
    main()