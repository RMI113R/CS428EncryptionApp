### emulator.py

import tkinter as tk
from tkinter import messagebox, filedialog
from utils import (
    encrypt_data,
    decrypt_data,
    save_encrypted_file,
    load_encrypted_file,
    get_combined_image_key,
    select_images,
    select_encrypted_file,
    prepare_file_for_encryption,
    extract_file_after_decryption,
    capture_image_and_save,
    generate_rsa_keys
)
import os
import datetime

ENCRYPTED_DIR = "encrypted_data"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

# New feature 1: Encryption history log
HISTORY_FILE = "encryption_history.txt"
def log_encryption(filename, method):
    with open(HISTORY_FILE, "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {method} -> {filename}\n")

# New feature 2: Button to view history
def show_history():
    clear_popup_frame()
    tk.Label(popup_frame, text="Encryption History", font=("Helvetica", 14, "bold"), bg='white').pack(pady=10)
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            for line in f.readlines()[-10:]:
                tk.Label(popup_frame, text=line.strip(), font=("Helvetica", 10), bg='white', anchor='w').pack(fill='x', padx=10)
    else:
        tk.Label(popup_frame, text="No history yet.", font=("Helvetica", 10), bg='white').pack(pady=10)

# New feature 3: Clear encrypted files directory
def clear_encrypted_files():
    for filename in os.listdir(ENCRYPTED_DIR):
        file_path = os.path.join(ENCRYPTED_DIR, filename)
        try:
            os.remove(file_path)
        except Exception:
            continue
    messagebox.showinfo("Cleared", "Encrypted files directory has been cleared.")

def run_encrypt():
    file_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Invalid file selected.")
        return

    data = prepare_file_for_encryption(file_path)

    def on_method_select(method):
        clear_popup_frame()

        tk.Label(popup_frame, text="Use camera or select existing images?", font=("Helvetica", 12), bg='white').pack(pady=10)
        tk.Button(popup_frame, text="📷 Use Camera", font=("Helvetica", 12), bg='#4CAF50', fg='white', command=lambda: complete_encryption(capture_image_and_save(), method)).pack(pady=5, ipadx=10, ipady=3)
        tk.Button(popup_frame, text="🖼️ Use Gallery", font=("Helvetica", 12), bg='#2196F3', fg='white', command=lambda: complete_encryption(select_images(), method)).pack(pady=5, ipadx=10, ipady=3)

    def complete_encryption(image_paths, method):
        clear_popup_frame()
        if not image_paths:
            messagebox.showerror("Error", "No images selected.")
            return

        if method == "RSA":
            private_key, public_key = generate_rsa_keys()
            key = public_key
            with open("private.pem", "wb") as f:
                f.write(private_key)
            messagebox.showinfo("Info", "RSA private key saved to 'private.pem'")
        else:
            key = get_combined_image_key(image_paths)
            # right after key = get_combined_image_key(image_paths)
            des_key = key[:24]
            print("🔑 3DES key (hex):", des_key.hex())

        encrypted = encrypt_data(data, key, method)

        filename = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
        if not filename:
            return

        full_path = os.path.join(ENCRYPTED_DIR, os.path.basename(filename))
        save_encrypted_file(full_path, encrypted)
        log_encryption(os.path.basename(filename), method)
        messagebox.showinfo("Success", f"Encrypted data saved to {full_path}")

    clear_popup_frame()
    tk.Label(popup_frame, text="Choose encryption method:", font=("Helvetica", 12), bg='white').pack(pady=10)
    tk.Button(popup_frame, text="AES", font=("Helvetica", 12), bg='#607D8B', fg='white', command=lambda: on_method_select("AES")).pack(pady=5, ipadx=10, ipady=3)
    tk.Button(popup_frame, text="Triple DES", font=("Helvetica", 12), bg='#9C27B0', fg='white', command=lambda: on_method_select("TripleDES")).pack(pady=5, ipadx=10, ipady=3)
    tk.Button(popup_frame, text="RSA", font=("Helvetica", 12), bg='#FF5722', fg='white', command=lambda: on_method_select("RSA")).pack(pady=5, ipadx=10, ipady=3)

def run_decrypt():
    encrypted_file_path = select_encrypted_file()
    if not encrypted_file_path:
        messagebox.showerror("Error", "No file selected.")
        return

    encrypted_data = load_encrypted_file(encrypted_file_path)
    method = encrypted_data[:3].decode()

    if method == "RSA":
        private_key_path = filedialog.askopenfilename(title="Select RSA Private Key")
        if not private_key_path:
            return
        with open(private_key_path, 'rb') as f:
            key = f.read()
    else:
        image_paths = select_images()
        if not image_paths:
            messagebox.showerror("Error", "No images selected.")
            return
        key = get_combined_image_key(image_paths)
        # right after key = get_combined_image_key(image_paths)
        des_key = key[:24]
        print("🔑 3DES key (hex):", des_key.hex())

    try:
        decrypted_data = decrypt_data(encrypted_data, key, method)
        ext, file_content = extract_file_after_decryption(decrypted_data)
        original_filename = os.path.splitext(os.path.basename(encrypted_file_path))[0]
        decrypted_filename = f"{original_filename}_decrypted{ext}"

        with open(decrypted_filename, "wb") as f:
            f.write(file_content)

        messagebox.showinfo("Success", f"Decrypted file saved as: {decrypted_filename}")
    except Exception:
        messagebox.showerror("Error", "Decryption failed. Wrong key or corrupted file.")

def clear_popup_frame():
    for widget in popup_frame.winfo_children():
        widget.destroy()

root = tk.Tk()
root.title("📱 Mobile Emulator - Image Encryptor")
root.geometry("320x620")
root.configure(bg='black')

screen_frame = tk.Frame(root, bg='white', bd=4, relief=tk.RIDGE)
screen_frame.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

tk.Label(screen_frame, text="Image Encryption App", font=("Helvetica", 22, "bold"), bg='white').pack(pady=10)

tk.Button(screen_frame, text="Encrypt File", font=("Helvetica", 14), bg='#4CAF50', fg='white', command=run_encrypt).pack(pady=5, ipadx=15, ipady=8)
tk.Button(screen_frame, text="Decrypt File", font=("Helvetica", 14), bg='#2196F3', fg='white', command=run_decrypt).pack(pady=5, ipadx=15, ipady=8)
tk.Button(screen_frame, text="View History", font=("Helvetica", 12), bg='#FFC107', fg='black', command=show_history).pack(pady=5, ipadx=10, ipady=5)
tk.Button(screen_frame, text="Clear Encrypted Files", font=("Helvetica", 12), bg='#F44336', fg='white', command=clear_encrypted_files).pack(pady=5, ipadx=10, ipady=5)
tk.Button(screen_frame, text="Exit", font=("Helvetica", 12), bg='gray', fg='white', command=root.quit).pack(pady=10, ipadx=10, ipady=5)

popup_frame = tk.Frame(screen_frame, bg='white')
popup_frame.pack(pady=10, fill='both', expand=True)

root.mainloop()
