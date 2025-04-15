
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

SALT_SIZE = 16
KEY_LEN = 32
ITERATIONS = 200000

def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=KEY_LEN, count=ITERATIONS, hmac_hash_module=SHA256)

def encrypt_file(file_path, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + cipher.nonce + tag + ciphertext)
    os.remove(file_path)

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    original_path = file_path[:-4]
    with open(original_path, 'wb') as f:
        f.write(data)
    os.remove(file_path)

def process_folder(folder_path, password, mode):
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            if mode == 'encrypt' and not full_path.endswith(".enc"):
                encrypt_file(full_path, password)
            elif mode == 'decrypt' and full_path.endswith(".enc"):
                decrypt_file(full_path, password)

class MerloSecureFolderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MerloSecureFolder")
        self.root.geometry("600x450")
        self.root.configure(bg="#000000")

        self.folder_path = tk.StringVar()
        self.password = tk.StringVar()

        try:
            self.logo_img = Image.open("logo.png").resize((120, 120))
            self.logo_photo = ImageTk.PhotoImage(self.logo_img)
            self.logo_label = tk.Label(root, image=self.logo_photo, bg="black")
            self.logo_label.pack(pady=10)
        except:
            pass

        tk.Label(root, text="MerloSecureFolder", font=("Consolas", 20, "bold"), bg="black", fg="#00FF00").pack()

        tk.Button(root, text="📁 Seleziona cartella", command=self.select_folder,
                  bg="#002200", fg="#00FF00", font=("Consolas", 11)).pack(pady=5)
        tk.Entry(root, textvariable=self.folder_path, width=60, font=("Consolas", 10), bg="#111111", fg="#00FF00", insertbackground="#00FF00").pack(pady=5)

        tk.Label(root, text="Password:", bg="black", fg="#00FF00", font=("Consolas", 11)).pack()
        tk.Entry(root, textvariable=self.password, show="*", width=30, font=("Consolas", 11), bg="#111111", fg="#00FF00", insertbackground="#00FF00").pack(pady=5)

        tk.Button(root, text="🔐 Cripta cartella", command=self.encrypt_folder,
                  bg="#220000", fg="red", font=("Consolas", 11), width=25).pack(pady=5)
        tk.Button(root, text="🔓 Decripta cartella", command=self.decrypt_folder,
                  bg="#001122", fg="#00FFFF", font=("Consolas", 11), width=25).pack(pady=5)

        self.status_label = tk.Label(root, text="", font=("Consolas", 10), bg="black", fg="yellow")
        self.status_label.pack(pady=10)

        footer = tk.Label(root, text="Powered by Roy Merlo", font=("Consolas", 9), bg="black", fg="#003300")
        footer.pack(side="bottom", pady=10)

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def encrypt_folder(self):
        if not self.folder_path.get() or not self.password.get():
            messagebox.showwarning("Attenzione", "Seleziona una cartella e inserisci una password.")
            return
        try:
            process_folder(self.folder_path.get(), self.password.get(), "encrypt")
            self.status_label.config(text="✅ Cartella criptata con successo.")
        except Exception as e:
            messagebox.showerror("Errore", str(e))

    def decrypt_folder(self):
        if not self.folder_path.get() or not self.password.get():
            messagebox.showwarning("Attenzione", "Seleziona una cartella e inserisci la password.")
            return
        try:
            process_folder(self.folder_path.get(), self.password.get(), "decrypt")
            self.status_label.config(text="✅ Cartella decriptata con successo.")
        except Exception as e:
            messagebox.showerror("Errore", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = MerloSecureFolderApp(root)
    root.mainloop()
