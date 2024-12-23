import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import os

class AESEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption Tool")

        # Create UI elements for encryption
        self.label_key = tk.Label(master, text="Key (min 8 characters):")
        self.label_key.pack()

        self.entry_key = tk.Entry(master, width=32)
        self.entry_key.pack()

        self.label_input_file = tk.Label(master, text="Input File:")
        self.label_input_file.pack()

        self.entry_input_file = tk.Entry(master, width=32)
        self.entry_input_file.pack()

        self.button_browse_input = tk.Button(master, text="Browse", command=self.browse_input_file)
        self.button_browse_input.pack()

        self.button_encrypt = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.button_encrypt.pack()

        # Create UI elements for decryption
        self.label_encrypted_file = tk.Label(master, text="Encrypted File:")
        self.label_encrypted_file.pack()

        self.entry_encrypted_file = tk.Entry(master, width=32)
        self.entry_encrypted_file.pack()

        self.button_browse_encrypted = tk.Button(master, text="Browse", command=self.browse_encrypted_file)
        self.button_browse_encrypted.pack()

        self.button_decrypt = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.button_decrypt.pack()

    def derive_key(self, password):
        # Derive a 16-byte key from the password using PBKDF2
        salt = os.urandom(16)  # Generate a random salt
        key = PBKDF2(password, salt, dkLen=16, count=1000000)  # Derive a key
        return key, salt

    def encrypt(self):
        password = self.entry_key.get()
        input_file = self.entry_input_file.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Key must be at least 8 characters long.")
            return

        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        key, salt = self.derive_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        padded_plaintext = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Create output file name
        base_name, ext = os.path.splitext(input_file)  # Split the input file into base name and extension
        output_file = f"{base_name}_encrypted{ext}"  # Create new file name

        # Write IV, salt, and ciphertext to output file
        with open(output_file, 'wb') as f:
            f.write(cipher.iv)
            f.write(salt)
            f.write(ciphertext)

        messagebox.showinfo("Success", f"Encryption successful. Encrypted file saved as {output_file}.")

    def decrypt(self):
        password = self.entry_key.get()
        encrypted_file = self.entry_encrypted_file.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Key must be at least 8 characters long.")
            return

        if not encrypted_file:
            messagebox.showerror("Error", "Please select an encrypted file.")
            return

        try:
            # Read IV, salt, and ciphertext from input file
            with open(encrypted_file, 'rb') as f:
                iv = f.read(16)
                salt = f.read(16)
                ciphertext = f.read()

            key = PBKDF2(password, salt, dkLen=16, count=1000000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)

            # Save the decrypted file with the original name (remove _encrypted)
            original_file = encrypted_file.replace("_encrypted", "")  # Remove the _encrypted part
            with open(original_file, 'wb') as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"Decryption successful. Decrypted file saved as {original_file}.")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Please check the key and input file.")

    def browse_input_file(self):
        file_path = filedialog.askopenfilename()
        self.entry_input_file.delete(0, tk.END)
        self.entry_input_file.insert(tk.END, file_path)

    def browse_encrypted_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", ".*")])
        self.entry_encrypted_file.delete(0, tk.END)
        self.entry_encrypted_file.insert(tk.END, file_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionApp(root)
    root.mainloop()