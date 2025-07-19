import os
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- Encryption/Decryption Functions with PKCS#7 Padding ---
def encrypt_image(image_path, key):
    """Encrypts an image file using Blowfish with PKCS#7 padding."""
    try:
        with open(image_path, 'rb') as f
            plaintext = f.read()
        padded_plaintext = pad(plaintext, Blowfish.block_size)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv
        ciphertext = iv + cipher.encrypt(padded_plaintext)
        return iv, ciphertext
    except FileNotFoundError:
        print(f"Error: Image file not found at {image_path}")
        return None, None
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None, None

def decrypt_image(iv, ciphertext, key):
    """Decrypts the image ciphertext using Blowfish and removes padding."""
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, Blowfish.block_size)
        return plaintext
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

# --- Basic Data Hiding Functions (Simplified LSB Embedding) ---
def embed_data_lsb(encrypted_data, secret_data):
    """Embeds secret data into the LSBs of the encrypted data (very basic)."""
    encrypted_list = list(encrypted_data)
    secret_bits = ''.join(format(byte, '08b') for byte in secret_data)
    data_index = 0
    modified_indices = []

    for i in range(len(encrypted_list)):
        if data_index < len(secret_bits):
            original_bit = encrypted_list[i] & 1
            new_bit = int(secret_bits[data_index])
            encrypted_list[i] = (encrypted_list[i] & ~1) | new_bit
            if original_bit != new_bit:
                modified_indices.append(i)
            data_index += 1
        else:
            break

    return bytes(encrypted_list)

def extract_data_lsb(modified_encrypted_data, num_bytes):
    """Extracts data from the LSBs of the modified encrypted data."""
    extracted_bits = ""
    for byte in modified_encrypted_data:
        extracted_bits += str(byte & 1)

    extracted_bytes = [int(extracted_bits[i:i+8], 2) for i in range(0, num_bytes * 8, 8)]
    return bytes(extracted_bytes)

# --- Main Execution ---
if __name__ == "__main__":
    image_file = r"C:\Users\acer\Desktop\SplProject\input.jpeg"  # Replace with the actual path to your JPEG image
    secret_data_to_hide = b"This is the secret data for the image."
    output_encrypted_image = "encrypted_image.jpeg"
    output_decrypted_image = "decrypted_image.jpeg"
    output_modified_encrypted = "encrypted_with_data.jpeg"

    # 1. Generate a random Blowfish key
    key = get_random_bytes(Blowfish.key_size[-1])
    print(f"Generated Blowfish Key: {key.hex()}")

    # 2. Encrypt the image
    iv, encrypted_data = encrypt_image(image_file, key)
    if encrypted_data:
        with open(output_encrypted_image, "wb") as f:
            f.write(iv + encrypted_data)
        print(f"Encrypted image saved to: {output_encrypted_image}")
    else:
        print("Encryption failed.")
        exit()

    # 3. Embed the secret data into the encrypted image
    modified_encrypted_data = embed_data_lsb(encrypted_data, secret_data_to_hide)
    with open(output_modified_encrypted, "wb") as f:
        f.write(iv + modified_encrypted_data)
    print(f"Encrypted image with hidden data saved to: {output_modified_encrypted}")
    print(f"Secret Data to Hide: {secret_data_to_hide.decode()}")

    # 4. Simulate reading the encrypted image with hidden data
    with open(output_modified_encrypted, "rb") as f:
        read_iv = f.read(Blowfish.block_size)
        read_encrypted_with_data = f.read()

    # 5. Extract the secret data
    extracted_secret_data = extract_data_lsb(read_encrypted_with_data, len(secret_data_to_hide))
    print(f"Extracted Secret Data: {extracted_secret_data.decode()}")

    # 6. Decrypt the *original* encrypted image (without the hidden data)
    with open(output_encrypted_image, "rb") as f:
        original_iv = f.read(Blowfish.block_size)
        original_encrypted = f.read()
    decrypted_image_data = decrypt_image(original_iv, original_encrypted, key)
    if decrypted_image_data:
        with open(output_decrypted_image, "wb") as f:
            f.write(decrypted_image_data)
        print(f"Decrypted image saved to: {output_decrypted_image}")
    else:
        print("Decryption failed.")
# import cv2
# import numpy as np
# from Crypto.Cipher import Blowfish
# import matplotlib.pyplot as plt
# import os

# # -------------------------------------
# # Blowfish Encryption Function
# def blowfish_encrypt(image_path, key):
#     print(f"Trying to load image from: {image_path}")  # Debugging the path
    
#     # Ensure the image exists
#     if not os.path.exists(image_path):
#         raise ValueError(f"Error: Unable to load image from {image_path}. Check the path.")
    
#     # Read the image in color (works for both .jpeg and .jpeg)
#     img = cv2.imread(image_path, cv2.IMREAD_COLOR)  # Try reading the image as a color image
    
#     # Check if image was loaded successfully
#     if img is None:
#         raise ValueError(f"Failed to load image from {image_path}. Check the file format and path.")
    
#     print(f"Image shape: {img.shape}")  # Debugging image shape
#     # Convert to grayscale if the image is in color
#     img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)  # Convert the image to grayscale
#     flat_img = img_gray.flatten()

#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)

#     # Pad image data to make its size a multiple of 8
#     padding_len = 8 - (len(flat_img) % 8)
#     padded_img = np.append(flat_img, [0] * padding_len)

#     encrypted_data = cipher.encrypt(bytes(padded_img))
    
#     return img_gray, encrypted_data, img_gray.shape, padding_len

# # -------------------------------------
# # Blowfish Decryption Function
# def blowfish_decrypt(encrypted_data, key, original_shape, padding_len):
#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)

#     decrypted_data = cipher.decrypt(encrypted_data)

#     # Remove padding first
#     if padding_len != 0:
#         decrypted_data = decrypted_data[:-padding_len]

#     # Ensure that the decrypted data matches the original shape (number of pixels)
#     decrypted_size = np.prod(original_shape)
    
#     print(f"Decrypted data length: {len(decrypted_data)}")
#     print(f"Expected size: {decrypted_size}")

#     if len(decrypted_data) != decrypted_size:
#         raise ValueError(f"Decrypted data size ({len(decrypted_data)}) does not match expected size ({decrypted_size}).")

#     # Reshape to the original image shape
#     decrypted_img = np.frombuffer(decrypted_data, dtype=np.uint8).reshape(original_shape)

#     return decrypted_img

# # -------------------------------------
# # LSB Data Embedding
# def embed_data(image, secret_data):
#     data = ''.join(format(ord(i), '08b') for i in secret_data)
#     img = image.copy()
#     h, w = img.shape
#     index = 0

#     for i in range(h):
#         for j in range(w):
#             if index < len(data):
#                 img[i, j] = (img[i, j] & ~1) | int(data[index])
#                 index += 1
#     return img

# # -------------------------------------
# # LSB Data Extraction
# def extract_data(image, length):
#     data = ''
#     h, w = image.shape
#     total_bits = length * 8
#     index = 0

#     for i in range(h):
#         for j in range(w):
#             if index < total_bits:
#                 data += str(image[i, j] & 1)
#                 index += 1
#     secret_message = ''.join(chr(int(data[i:i+8], 2)) for i in range(0, total_bits, 8))
#     return secret_message

# # -------------------------------------
# # PSNR Calculation
# def calculate_psnr(original, decrypted):
#     mse = np.mean((original - decrypted) ** 2)
#     if mse == 0:
#         return float('inf')
#     max_pixel = 255.0
#     return 20 * np.log10(max_pixel / np.sqrt(mse))

# # -------------------------------------
# # MAIN PROCESS
# if __name__ == "__main__":
#     # ✅ Correct path to input JPEG image
#     image_path = r"C:\Users\acer\Desktop\SplProject\input.jpeg"  # Make sure the file is here!
#     key = b'secret123'
#     secret_message = "TopSecret"

#     # 1. Encrypt the original image
#     try:
#         original_img, encrypted_data, shape, padding_len = blowfish_encrypt(image_path, key)
#     except ValueError as e:
#         print(f"Error: {e}")
#         exit()

#     # Save encrypted image array for LSB hiding
#     encrypted_img = np.frombuffer(encrypted_data, dtype=np.uint8)[:shape[0]*shape[1]].reshape(shape)
#     cv2.imwrite("encrypted_image.jpeg", encrypted_img)

#     # 2. Embed data into encrypted image
#     embedded_img = embed_data(encrypted_img.copy(), secret_message)
#     cv2.imwrite("embedded_image.jpeg", embedded_img)

#     # 3. Extract data from the embedded image
#     extracted_message = extract_data(embedded_img.copy(), len(secret_message))
#     print("Extracted Secret:", extracted_message)

#     # 4. Decrypt the *original encrypted data* (not from embedded image!)
#     try:
#         decrypted_img = blowfish_decrypt(encrypted_data, key, shape, padding_len)
#     except ValueError as e:
#         print(f"Decryption error: {e}")
#         exit()
#     cv2.imwrite("decrypted_image.jpeg", decrypted_img)

#     # 5. PSNR Comparison
#     psnr_value = calculate_psnr(original_img, decrypted_img)
#     print(f"PSNR between original and decrypted image: {psnr_value:.2f} dB")

#     # 6. Show images
#     plt.figure(figsize=(10,8))

#     plt.subplot(2,2,1)
#     plt.title("Original Image")
#     plt.imshow(original_img, cmap='gray')
#     plt.axis('off')

#     plt.subplot(2,2,2)
#     plt.title("Encrypted Image")
#     plt.imshow(encrypted_img, cmap='gray')
#     plt.axis('off')

#     plt.subplot(2,2,3)
#     plt.title("Data Embedded Image")
#     plt.imshow(embedded_img, cmap='gray')
#     plt.axis('off')

#     plt.subplot(2,2,4)
#     plt.title("Decrypted Image")
#     plt.imshow(decrypted_img, cmap='gray')
#     plt.axis('off')

#     plt.tight_layout()
#     plt.show()
