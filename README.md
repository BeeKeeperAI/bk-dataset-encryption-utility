# BeeKeeperAI Encryption Utility

This utility, `bkai-encrypt.py` provides a secure method for encrypting and decrypting files for use with the EscrowAI platform. It is designed to be run at the command line using both an input, output, and a pre-created Content Encrpytion Key (CEK).

## Features

- Encrypt files using AES-256-GCM.
- Decrypt files encrypted by this tool.
- Utilize PBKDF2 key derivation for enhanced security.

## Requirements

- Python 3.6 or newer.
- Cryptography library.
- An existing Content Encryption Key (CEK)

## Installation

Before you can use this script, ensure you have Python installed, you already have an existing Content Encryption Key(CEK), and you are executing the commands in this README in the folder that contains this script.

### Environment Setup

To keep your python dependencies local to this script, you should use python's virtual environment module. You can do this by running the following commands:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then, install the required Python `cryptography` package using pip:

```bash
pip install cryptography
```

## Usage

### Encrypting a Folder

To encrypt a folder, run the script with the encrypt action, specifying the paths for the input folder, your CEK, and the desired output folder for the encrypted content:

```bash
python3 bkai-encrypt.py encrypt --input /path/to/your/unencrypted/folder --key /path/to/your/secret.key --output /path/to/your/encrypted/folder
```

### Encrypting a File

To encrypt a file, run the script with the encrypt action, specifying the paths for the input file, your CEK, and the desired output file for the encrypted content:

```bash
python3 bkai-encrypt.py encrypt --input /path/to/your/file.txt --key /path/to/your/secret.key --output /path/to/encrypted/file.bkenc
```

### Decrypting a Folder

To decrypt a folder previously encrypted by this tool, use the decrypt action with the paths to the encrypted folder, your CEK, and the desired output folder for the decrypted content:

```bash
python bkai-encrypt.py decrypt --input /path/to/your/encrypted/folder --key /path/to/your/secret.key --output /path/to/your/unencrypted/folder
```

### Decrypting a File

To decrypt a file previously encrypted by this tool, use the decrypt action with the paths to the encrypted file, your CEK, and the desired output file for the decrypted content:

```bash
python bkai-encrypt.py decrypt --input /path/to/encrypted/file.bkenc --key /path/to/your/secret.key --output /path/to/decrypted/file.txt
```

After encrypting your files, you can securely upload them to Azure Blob Storage for safekeeping. This script does not cover the upload process, but you can use Azure's CLI tools or SDKs in your preferred programming language to upload the encrypted files.

## Security Note

- Always keep your Content Encrpytion Key (CEK) secure and do not share it.
- Always validate you have effectively uploaded encrypted files
