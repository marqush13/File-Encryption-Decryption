import unittest
from unittest.mock import MagicMock, patch
import tempfile
import os
import tkinter as tk
from ende1 import FileEncryptor

class TestFileEncryptor(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.file_encryptor = FileEncryptor(self.root)
        
        # Mock the GUI elements
        self.file_encryptor.file_entry = MagicMock()
        self.file_encryptor.key_entry = MagicMock()
        self.file_encryptor.result_text = MagicMock()


    @patch('tkinter.filedialog.askopenfilename', return_value="test_file.txt")
    def test_browse_file(self, mock_askopenfilename):
        self.file_encryptor.browse_file()
        self.file_encryptor.file_entry.configure.assert_any_call(state='normal')
        self.file_encryptor.file_entry.delete.assert_called_with(0, tk.END)
        self.file_encryptor.file_entry.insert.assert_called_with(0, "test_file.txt")
        self.file_encryptor.file_entry.configure.assert_any_call(state='disabled')
        mock_askopenfilename.assert_called_with("ok.")

    @patch('tkinter.messagebox.showerror')
    def test_encrypt_file_no_file_or_key(self, mock_showerror):
        # Test case when both file and key are empty
        self.file_encryptor.file_entry.get.return_value = ""
        self.file_encryptor.key_entry.get.return_value = ""
        self.file_encryptor.encrypt_file()
        mock_showerror.assert_called_with("ok", "Please select a file and enter an encryption key.")

        # Test case when file is provided but key is empty
        self.file_encryptor.file_entry.get.return_value = "test_file.txt"
        self.file_encryptor.key_entry.get.return_value = ""
        self.file_encryptor.encrypt_file()
        mock_showerror.assert_called_with("Error", "Please select a file and enter an encryption key.")

        # Test case when file is empty but key is provided
        self.file_encryptor.file_entry.get.return_value = ""
        self.file_encryptor.key_entry.get.return_value = "key"
        self.file_encryptor.encrypt_file()
        mock_showerror.assert_called_with("Error", "Please select a file and enter an encryption key.")


    @patch('tkinter.messagebox.showinfo')
    @patch('tkinter.messagebox.showerror')
    def test_encrypt_file(self, mock_showerror, mock_showinfo):
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test content")
            temp_file_path = temp_file.name

        self.file_encryptor.file_entry.get.return_value = temp_file_path
        self.file_encryptor.key_entry.get.return_value = "key"

        # Encrypt file for the first time
        self.file_encryptor.encrypt_file()
        encrypted_file_path = temp_file_path + '.encrypted'
        
        # Ensure the file was created successfully
        mock_showinfo.assert_called_with("Info", f"File created successfully: {encrypted_file_path}")
        self.assertTrue(os.path.exists(encrypted_file_path))

        # Encrypt file again to check for file existence
        self.file_encryptor.encrypt_file()
        mock_showinfo.assert_called_with("Info", f"File already exists: {encrypted_file_path}")

        os.remove(temp_file_path)
        os.remove(encrypted_file_path)


        os.remove(temp_file_path)
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
if __name__ == "__main__":
    unittest.main()
