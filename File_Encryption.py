import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os

class FileEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption and Decryption")
        self.root.attributes("-fullscreen", True)  # Fullscreen window
        self.root.configure(bg='#2d2d2d')  # Dark gray background color

        # Set ttk style and theme
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Choose a ttk theme

        frame = ttk.Frame(self.root, padding="20", style='Frame.TFrame')
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)  # Center the frame

        ttk.Label(frame, text="Select File:", style='TLabel').grid(row=0, column=0, sticky=tk.W, pady=10)
        self.file_entry = ttk.Entry(frame, width=50, state='disabled', style='File.TEntry')
        self.file_entry.grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(frame, text="Browse", command=self.browse_file, style='Browse.TButton').grid(row=0, column=2, padx=10, pady=10)

        ttk.Label(frame, text="Encryption Key:", style='TLabel').grid(row=1, column=0, sticky=tk.W, pady=10)
        self.key_entry = ttk.Entry(frame, show='*', width=50, style='Key.TEntry')
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Encrypt", command=self.encrypt_file, style='Encrypt.TButton').grid(row=2, column=1, padx=10, pady=20)
        ttk.Button(frame, text="Decrypt", command=self.decrypt_file, style='Decrypt.TButton').grid(row=2, column=2, padx=10, pady=20)

        self.result_text = tk.Text(frame, height=6, width=60, wrap=tk.WORD, state='disabled', bg='#3d3d3d', fg='#ffffff', font=('Helvetica', 11))
        self.result_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.result_text.yview, style='TScrollbar')
        scrollbar.grid(row=3, column=3, sticky=tk.NS)
        self.result_text['yscrollcommand'] = scrollbar.set

        ttk.Button(self.root, text="Exit", command=self.exit_fullscreen, style='Exit.TButton').pack(side=tk.BOTTOM, pady=10)

        # Apply a more modern style to the widgets
        self.apply_custom_styles()

    def apply_custom_styles(self):
        # Custom style settings
        self.style.configure('Browse.TButton', foreground='#ffffff', background='#1e90ff', font=('Helvetica', 12, 'bold'), padding=5)
        self.style.configure('Encrypt.TButton', foreground='#ffffff', background='#32cd32', font=('Helvetica', 12, 'bold'), padding=5)
        self.style.configure('Decrypt.TButton', foreground='#ffffff', background='#ffa07a', font=('Helvetica', 12, 'bold'), padding=5)
        self.style.configure('Exit.TButton', foreground='#ffffff', background='#d9534f', font=('Helvetica', 12, 'bold'), padding=5)
        self.style.configure('TLabel', foreground='#ffffff', background='#2d2d2d', font=('Helvetica', 12))
        self.style.configure('File.TEntry', foreground='#ffffff', fieldbackground='#3d3d3d', background='#2d2d2d', font=('Helvetica', 11))
        self.style.configure('Key.TEntry', foreground='#ffffff', fieldbackground='#3d3d3d', background='#2d2d2d', font=('Helvetica', 11))
        self.style.configure('TText', foreground='#ffffff', background='#3d3d3d', font=('Helvetica', 11))
        self.style.configure('TScrollbar', troughcolor='#3d3d3d', background='#4CAF50', bordercolor='#333333', arrowcolor='#ffffff')
        self.style.configure('Frame.TFrame', background='#2d2d2d')

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.configure(state='normal')
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.configure(state='disabled')

    def encrypt_file(self):
        file_path = self.file_entry.get()
        key = self.key_entry.get()

        if not file_path or not key:
            messagebox.showerror("Error", "Please select a file and enter an encryption key.")
            return

        try:
            # Read file content
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Encrypt the data using XOR cipher with the key
            encrypted_data = self.xor_cipher(plaintext, key.encode())

            # Save encrypted file
            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            self.result_text.configure(state='normal')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, f"Encryption successful. Encrypted file saved as {encrypted_file_path}\n")
            self.result_text.configure(state='disabled')

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

    def decrypt_file(self):
        file_path = self.file_entry.get()
        key = self.key_entry.get()

        if not file_path or not key:
            messagebox.showerror("Error", "Please select a file and enter an encryption key.")
            return

        try:
            # Read encrypted file content
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt the data using XOR cipher with the key
            decrypted_data = self.xor_cipher(encrypted_data, key.encode())

            # Remove .encrypted extension for decrypted file
            decrypted_file_path = os.path.splitext(file_path)[0]

            # Save decrypted file
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)




            self.result_text.configure(state='normal')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, f"Decryption successful. Decrypted file saved as {decrypted_file_path}\n")
            self.result_text.configure(state='disabled')

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

    def xor_cipher(self, data, key):
        # Simple XOR cipher implementation
        key_length = len(key)
        encrypted_data = bytearray(data)
        for i in range(len(data)):
            encrypted_data[i] ^= key[i % key_length]
        return bytes(encrypted_data)

    def exit_fullscreen(self):
        self.root.attributes("-fullscreen", False)
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptor(root)
    root.mainloop()
