# BeeKeeperAI Encryption Utility

This utility, `bkai_encrypt.py` provides a secure method for encrypting and decrypting files for use with the EscrowAI platform. It is designed to be run at the command line using both an input, output, and a pre-created Content Encrpytion Key (CEK).

## Features

- Encrypt files using AES-256-GCM.
- Decrypt files encrypted by this tool.
- Utilize PBKDF2 key derivation for enhanced security.
- Optional zipping of the encrypted or decrypted output.
- Debug mode for verbose output during encryption or decryption processes.

## Requirements

- Python 3.6 or newer.
- Cryptography library.
- An existing Content Encryption Key (CEK)

## Installation

Ensure you have Python installed, you already have an existing Content Encryption Key (CEK), and you are executing the commands in the folder that contains this script.

### Environment Setup

It's recommended to use Python's virtual environment to keep dependencies local:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then, install the required Python `cryptography` package using pip:

```bash
pip install cryptography 
```

## Usage

### Encrypting a Folder or File

To encrypt, specify the `encrypt` action, the paths for the input folder or file, your CEK, and the desired output folder or file for the encrypted content. Add `--zip <zip_file_name>` to optionally zip the output.


```bash
python3 bkai_encrypt.py encrypt --input /path/to/your/input --key /path/to/your/cek.key --output /path/to/your/output --zip optional_zip_name
```

### Decrypting a Folder or File

To decrypt, use the `decrypt` action with the paths to the encrypted folder or file, your CEK, and the desired output location for the decrypted content. Add `--zip <zip_file_name>` to optionally zip the output.


```bash
python bkai_encrypt.py decrypt --input /path/to/your/encrypted/input --key /path/to/your/cek.key --output /path/to/your/output --zip optional_zip_name
```

### Debug Mode

For verbose output during the encryption or decryption process, add the `--debug` flag:

```bash
python bkai_encrypt.py encrypt --input /path/to/your/input --key /path/to/your/cek.key --output /path/to/your/output --debug
```

### Running Tests

This utility is tested using Python's Unit Testing Framework with tests in [tests/test_encrypt.py](tests/test_encrypt.py). In order to execute the tests, you should install the cryptography dependency and run the following command:

```bash
python3 -m unittest tests/test_encrypt.py
```

### After Encryption

After encrypting your files, you can securely upload them to Azure Blob Storage for safekeeping. This script does not cover the upload process, but you can use Azure's CLI tools or SDKs in your preferred programming language to upload the encrypted files.

## Security Note

- Always keep your Content Encrpytion Key (CEK) secure and do not share it.
- Always validate you have effectively uploaded encrypted files

## Disclaimer

This utility is provided as-is with no guarantees or warranties regarding its use or performance. Use it at your own risk. Please make sure you understand how to handle encryption keys securely before using this tool.

## License

Copyright (c) 2024 BeeKeeperAI, Inc.

Use of this source code is governed by an MIT license that can be found in the LICENSE.txt file or at <https://opensource.org/license/mit>.
