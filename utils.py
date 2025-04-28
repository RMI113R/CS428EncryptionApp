# utils.py

from hashlib import sha256
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from tkinter import Tk, filedialog
import struct
import os
import cv2

def get_image_key(image_path):
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()
    return sha256(image_data).digest()

def get_combined_image_key(image_paths):
    combined = b""
    for path in sorted(image_paths):
        with open(path, 'rb') as f:
            img_data = f.read()
            combined += sha256(img_data).digest()
    return sha256(combined).digest()

def generate_rsa_keys(seed: bytes = None, bits: int = 2048):
    """
    Generate a 2048-bit RSA key pair.
    If seed is provided, keypair is derived deterministically from that seed.
    """
    if seed is None:
        key = RSA.generate(bits)
    else:
        counter = 0
        def randfunc(n):
            nonlocal counter
            out = b""
            while len(out) < n:
                out += sha256(seed + counter.to_bytes(4, 'big')).digest()
                counter += 1
            return out[:n]
        key = RSA.generate(bits, randfunc=randfunc)

    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_data(data: bytes, key: bytes, method: str) -> bytes:
    if method == "AES":
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return b"AES" + cipher.nonce + tag + ciphertext

    elif method == "TripleDES":
        des_key = key[:24]
        cipher = DES3.new(des_key, DES3.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return b"3DS" + cipher.nonce + tag + ciphertext

    elif method == "RSA":
        # hybrid RSA + AES:
        # 1) generate AES session key
        session_key = get_random_bytes(32)
        # 2) wrap session key under RSA
        public_key = RSA.import_key(key)
        rsa_cipher = PKCS1_OAEP.new(public_key)
        wrapped_key = rsa_cipher.encrypt(session_key)
        # 3) AES/EAX encrypt the payload
        aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = aes.encrypt_and_digest(data)
        # 4) pack: [wrapped_len(2)][wrapped_key][nonce(16)][tag(16)][ciphertext]
        packed = (
            struct.pack('>H', len(wrapped_key)) +
            wrapped_key +
            aes.nonce +
            tag +
            ciphertext
        )
        return b"RSA" + packed

    else:
        raise ValueError(f"Unknown encryption method: {method}")

def decrypt_data(encrypted_data: bytes, key: bytes, method: str) -> bytes:
    prefix = encrypted_data[:3]
    content = encrypted_data[3:]

    if prefix == b"AES":
        nonce = content[:16]
        tag = content[16:32]
        ciphertext = content[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    elif prefix == b"3DS":
        des_key = key[:24]
        nonce_size = 16
        tag_size = DES3.block_size  # 8
        nonce = content[:nonce_size]
        tag = content[nonce_size:nonce_size + tag_size]
        ciphertext = content[nonce_size + tag_size:]
        cipher = DES3.new(des_key, DES3.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    elif prefix == b"RSA":
        # unpack hybrid blob
        wrapped_len = struct.unpack('>H', content[:2])[0]
        idx = 2
        wrapped_key = content[idx:idx + wrapped_len]
        idx += wrapped_len
        nonce = content[idx:idx + 16]; idx += 16
        tag = content[idx:idx + 16]; idx += 16
        ciphertext = content[idx:]
        # unwrap session key
        priv = RSA.import_key(key)
        rsa_cipher = PKCS1_OAEP.new(priv)
        session_key = rsa_cipher.decrypt(wrapped_key)
        # AES decrypt
        aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        return aes.decrypt_and_verify(ciphertext, tag)

    else:
        raise ValueError(f"Unknown encryption prefix: {prefix}")

def save_encrypted_file(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)

def load_encrypted_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def select_images():
    root = Tk()
    root.withdraw()
    image_paths = filedialog.askopenfilenames(
        title="Select key images",
        filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
    )
    return list(image_paths)

def select_encrypted_file():
    return filedialog.askopenfilename(
        title="Select encrypted message",
        filetypes=[("Encrypted files", "*.bin"), ("All files", "*.*")]
    )

def prepare_file_for_encryption(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        file_data = f.read()
    ext_bytes = os.path.splitext(file_path)[1].encode()
    return struct.pack('B', len(ext_bytes)) + ext_bytes + file_data

def extract_file_after_decryption(decrypted_data: bytes):
    ext_len = decrypted_data[0]
    ext = decrypted_data[1:1 + ext_len].decode()
    file_content = decrypted_data[1 + ext_len:]
    return ext, file_content

def capture_image_and_save():
    print("📷 Opening camera... Press 's' to capture and save, or 'q' to cancel.")
    cap = cv2.VideoCapture(0)
    saved_path = None

    while True:
        ret, frame = cap.read()
        if not ret:
            print("Failed to capture frame.")
            break

        cv2.imshow("Capture Image", frame)
        key = cv2.waitKey(1)

        if key == ord('s'):
            save_path = filedialog.asksaveasfilename(
                title="Save captured image",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            if save_path:
                cv2.imwrite(save_path, frame)
                print(f"✅ Image saved to: {save_path}")
                saved_path = save_path
            break

        elif key == ord('q'):
            print("Capture canceled.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return [saved_path] if saved_path else []
