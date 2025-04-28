import os
from tkinter import filedialog
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

ENCRYPTED_DIR = "encrypted_data"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def main():
    print("🔐 Image-based Encryptor")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Select an option (1 or 2): ").strip()

    if choice == "1":
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path or not os.path.exists(file_path):
            print("Invalid file.")
            return

        data = prepare_file_for_encryption(file_path)

        print("Choose encryption method:")
        print("1. AES")
        print("2. Triple DES")
        print("3. RSA")
        method_choice = input("Enter choice (1/2/3): ").strip()

        if method_choice == "1":
            method = "AES"
        elif method_choice == "2":
            method = "TripleDES"
        elif method_choice == "3":
            method = "RSA"
        else:
            print("Invalid choice.")
            return

        print("Would you like to:")
        print("1. Take a photo for encryption key")
        print("2. Select existing image(s) for key")
        image_choice = input("Choose (1 or 2): ").strip()

        if image_choice == "1":
            image_paths = capture_image_and_save()
        elif image_choice == "2":
            image_paths = select_images()
        else:
            print("Invalid choice.")
            return

        if not image_paths:
            print("No images selected.")
            return

        if method == "RSA":
            private_key, public_key = generate_rsa_keys()
            key = public_key
            with open("private.pem", "wb") as f:
                f.write(private_key)
            print("Private key saved to 'private.pem'")
        else:
            key = get_combined_image_key(image_paths)

        encrypted = encrypt_data(data, key, method)
        filename = input("Enter a filename to save (e.g., secret.bin): ")
        full_path = os.path.join(ENCRYPTED_DIR, filename)
        save_encrypted_file(full_path, encrypted)
        print(f"Encrypted data saved to {full_path}")

    elif choice == "2":
        encrypted_file_path = select_encrypted_file()
        if not encrypted_file_path:
            print("No file selected.")
            return

        encrypted_data = load_encrypted_file(encrypted_file_path)
        method = encrypted_data[:3].decode()

        if method == "RSA":
            private_key_path = filedialog.askopenfilename(title="Select RSA Private Key")
            if not private_key_path:
                print("No key selected.")
                return
            with open(private_key_path, 'rb') as f:
                key = f.read()
        else:
            image_paths = select_images()
            if not image_paths:
                print("No images selected.")
                return
            key = get_combined_image_key(image_paths)

        try:
            decrypted_data = decrypt_data(encrypted_data, key, method)
            ext, file_content = extract_file_after_decryption(decrypted_data)
            original_filename = os.path.splitext(os.path.basename(encrypted_file_path))[0]
            decrypted_filename = f"{original_filename}_decrypted{ext}"

            with open(decrypted_filename, "wb") as f:
                f.write(file_content)

            print(f"Decrypted file saved as: {decrypted_filename}")
        except Exception as e:
            print("Decryption failed. Wrong key or corrupted file.")

if __name__ == "__main__":
    main()