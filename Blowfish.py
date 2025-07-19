import os
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- Encryption/Decryption Functions with PKCS#7 Padding ---
def encrypt_image(image_path, key):
    """Encrypts an image file using Blowfish with PKCS#7 padding."""
    try:
        with open(image_path, 'rb') as f:
            plaintext = f.read()
        padded_plaintext = pad(plaintext, Blowfish.block_size)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv, ciphertext
    except FileNotFoundError:
        print(f"[Error] File not found: {image_path}")
    except Exception as e:
        print(f"[Error] Encryption failed: {e}")
    return None, None

def decrypt_image(iv, ciphertext, key):
    """Decrypts the ciphertext and removes padding."""
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, Blowfish.block_size)
        return plaintext
    except Exception as e:
        print(f"[Error] Decryption failed: {e}")
        return None

# --- LSB Data Embedding ---
def embed_data_lsb(encrypted_data, secret_data):
    """Embeds secret data into the LSBs of encrypted data."""
    encrypted_list = list(encrypted_data)
    secret_bits = ''.join(format(byte, '08b') for byte in secret_data)
    data_index = 0

    for i in range(len(encrypted_list)):
        if data_index < len(secret_bits):
            new_bit = int(secret_bits[data_index])
            encrypted_list[i] = (encrypted_list[i] & ~1) | new_bit
            data_index += 1
        else:
            break

    return bytes(encrypted_list)

def extract_data_lsb(data, num_bytes):
    """Extracts secret data from the LSBs of the modified encrypted data."""
    extracted_bits = ''.join(str(byte & 1) for byte in data)
    extracted_bytes = [int(extracted_bits[i:i+8], 2) for i in range(0, num_bytes * 8, 8)]
    return bytes(extracted_bytes)

# --- Main Execution ---
if __name__ == "__main__":
    # Input / Output paths
    input_image = r"C:\Users\acer\Desktop\SplProject\imgencry\input.jpeg"
    output_encrypted = "encrypted_image.jpeg"
    output_with_hidden = "encrypted_with_data.jpeg"
    output_decrypted = "decrypted_image.jpeg"
    secret_data = b"This is the secret data for the image."

    # Step 1: Generate Blowfish key
    key = get_random_bytes(Blowfish.key_size[-1])
    print(f"\n[Info] Generated Blowfish Key: {key.hex()}")

    # Step 2: Encrypt image
    iv, encrypted_data = encrypt_image(input_image, key)
    if iv and encrypted_data:
        try:
            with open(output_encrypted, "wb") as f:
                f.write(iv + encrypted_data)
            print(f"[Info] Encrypted image saved to: {output_encrypted}")
        except Exception as e:
            print(f"[Error] Saving encrypted image failed: {e}")
            exit(1)
    else:
        exit(1)

    # Step 3: Embed secret data into encrypted image
    modified_data = embed_data_lsb(encrypted_data, secret_data)
    try:
        with open(output_with_hidden, "wb") as f:
            f.write(iv + modified_data)
        print(f"[Info] Encrypted image with hidden data saved to: {output_with_hidden}")
        print(f"[Info] Secret Data Embedded: {secret_data.decode()}")
    except Exception as e:
        print(f"[Error] Failed to write modified image: {e}")
        exit(1)

    # Step 4: Extract the secret data back
    try:
        with open(output_with_hidden, "rb") as f:
            read_iv = f.read(Blowfish.block_size)
            read_data = f.read()
        extracted = extract_data_lsb(read_data, len(secret_data))
        print(f"[Info] Extracted Secret Data: {extracted.decode()}")
    except Exception as e:
        print(f"[Error] Extraction failed: {e}")

    # Step 5: Decrypt the original image (without LSB embedding)
    try:
        with open(output_encrypted, "rb") as f:
            original_iv = f.read(Blowfish.block_size)
            original_cipher = f.read()
        decrypted = decrypt_image(original_iv, original_cipher, key)
        if decrypted:
            with open(output_decrypted, "wb") as f:
                f.write(decrypted)
            print(f"[Info] Decrypted image saved to: {output_decrypted}")
        else:
            print("[Error] Image decryption failed.")
    except Exception as e:
        print(f"[Error] Failed to decrypt original image: {e}")
