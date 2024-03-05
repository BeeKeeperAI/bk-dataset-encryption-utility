# BeeKeeperAI Encryption Utility

This utility, `bkai-encrypt.py` provides a secure method for encrypting and decrypting files for use with the EscrowAI platform. It is designed to be run at the command line using both an input, output, and a pre-created Content Encrpytion Key (CEK).

## Features

- Encrypt files using AES-256-GCM.
- Decrypt files encrypted by this tool.
- Utilize PBKDF2 key derivation for enhanced security.

## Requirements

- Python 3.6 or newer.
- Cryptography library.

## Installation

Before you can use this script, ensure you have Python installed on your system. Then, install the required Python `cryptography` package using pip:

```bash
pip install cryptography
```

## Before Using Utility, Generate a Content Encryption Key

Before encrypting files, you need to create a secret.key file outside of this script. You can generate a secure key using OpenSSL with the following command:

```bash
openssl rand -out secret.key 32
```

This command creates a 32-byte random key and saves it to secret.key. Keep this key safe and secure, as you will need it for both encryption and decryption of your files. You may also choose to use the EscrowAI encryption tool to wrap this key to create your Wrapped Content Encryption Key (WCEK)

## Usage

### Encrypting a File

To encrypt a file, run the script with the encrypt action, specifying the paths for the input file, the key file (your secret.key), and the desired output file for the encrypted content:

```bash
python bkai-encrypt.py encrypt --input /path/to/your/file.txt --key /path/to/your/secret.key --output /path/to/encrypted/file.enc
```

### Decrypting a File

To decrypt a file previously encrypted by this tool, use the decrypt action with the paths to the encrypted file, the key file, and the desired output file for the decrypted content:

```bash
python bkai-encrypt.py decrypt --input /path/to/encrypted/file.enc --key /path/to/your/secret.key --output /path/to/decrypted/file.txt
```

## Uploading to Azure Blob Storage

After encrypting your files, you can securely upload them to Azure Blob Storage for safekeeping. This script does not cover the upload process, but you can use Azure's CLI tools or SDKs in your preferred programming language to upload the encrypted files.

## Security Note

- Always keep your secret.key file secure and do not share it.
- Always validate you have effectively uploaded encrypted files
