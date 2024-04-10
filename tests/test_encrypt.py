import unittest
import os
from pathlib import Path
import tempfile

# Give our test script a chance to access bkai_encrypt in the parent folder.
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from bkai_encrypt import encrypt_file, decrypt_file, encrypt_folder, decrypt_folder

class TestEncryptionUtils(unittest.TestCase):
    def setUp(self):
        # Temporary directory for testing
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_file_path = Path(self.test_dir.name) / "test.txt"
        self.encrypted_file_path = Path(self.test_dir.name) / "test.encrypted"
        self.decrypted_file_path = Path(self.test_dir.name) / "test.decrypted"
        self.key_path = Path(self.test_dir.name) / "CEK"

        # Write a test file and a key
        with open(self.test_file_path, 'w') as f:
            f.write("This is a test.")
        with open(self.key_path, 'wb') as f:
            f.write(os.urandom(32))  # Simple key for testing; adjust as needed

    def tearDown(self):
        self.test_dir.cleanup()

    def test_encrypt_decrypt_file(self):
        # Test encryption
        encrypt_file(self.test_file_path, self.key_path, self.encrypted_file_path)
        self.assertTrue(self.encrypted_file_path.exists())

        # Test decryption
        decrypt_file(self.encrypted_file_path, self.key_path, self.decrypted_file_path)
        self.assertTrue(self.decrypted_file_path.exists())

        # Verify the decrypted content matches the original content
        with open(self.test_file_path, 'r') as original, open(self.decrypted_file_path, 'r') as decrypted:
            self.assertEqual(original.read(), decrypted.read())

    def test_encrypt_decrypt_folder(self):
        # Create a test folder structure
        test_folder = Path(self.test_dir.name) / "test_folder"
        test_folder.mkdir()
        (test_folder / "subfolder").mkdir()
        with open(test_folder / "file1.txt", 'w') as f:
            f.write("File 1 content")
        with open(test_folder / "subfolder/file2.txt", 'w') as f:
            f.write("File 2 content")

        encrypted_folder = Path(self.test_dir.name) / "encrypted_folder"
        decrypted_folder = Path(self.test_dir.name) / "decrypted_folder"

        # Validate the folders were created
        self.assertTrue(test_folder.exists())
        encrypted_folder.mkdir(parents=True, exist_ok=True) # Ensure the folder exists
        self.assertTrue(encrypted_folder.exists())
        decrypted_folder.mkdir(parents=True, exist_ok=True) # Ensure the folder exists
        self.assertTrue(decrypted_folder.exists())

        # Test folder encryption
        encrypt_folder(test_folder, self.key_path, encrypted_folder)
        self.assertTrue(any(encrypted_folder.rglob('*')), "Encryption folder is empty")

        # Test folder decryption
        decrypt_folder(encrypted_folder, self.key_path, decrypted_folder)
        # List the files in the decrypted_folder
        self.assertTrue(any(decrypted_folder.rglob('*')), "Decrypted folder is empty")

        # Verify content of the decrypted files
        with open(decrypted_folder / "file1.txt", 'r') as f:
            self.assertEqual(f.read(), "File 1 content")
        with open(decrypted_folder / "subfolder/file2.txt", 'r') as f:
            self.assertEqual(f.read(), "File 2 content")

    def test_encrypt_decrypt_with_rstrip_poisoned_bytes(self):
        # Generate a key that ends with bytes that could be removed by rstrip
        key_with_trimmable_bytes = os.urandom(30) + b'\x00\x20'
        with open(self.key_path, 'wb') as f:
            f.write(key_with_trimmable_bytes)

        # Proceed with encryption and decryption using this special key
        encrypt_file(self.test_file_path, self.key_path, self.encrypted_file_path)
        self.assertTrue(self.encrypted_file_path.exists())

        decrypt_file(self.encrypted_file_path, self.key_path, self.decrypted_file_path)
        self.assertTrue(self.decrypted_file_path.exists())

        # Verify the decrypted content matches the original content
        with open(self.test_file_path, 'r') as original, open(self.decrypted_file_path, 'r') as decrypted:
            self.assertEqual(original.read(), decrypted.read())

# Run the tests
if __name__ == '__main__':
    unittest.main()