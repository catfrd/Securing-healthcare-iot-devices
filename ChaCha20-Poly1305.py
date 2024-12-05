from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import csv
import os

def encrypt_value(value, key, nonce):
    """Encrypt a string value using ChaCha20-Poly1305."""
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, value.encode(), None)
    return ciphertext.hex()

def decrypt_value(encrypted_value, key, nonce):
    """Decrypt a string value using ChaCha20-Poly1305."""
    aead = ChaCha20Poly1305(key)
    decrypted = aead.decrypt(nonce, bytes.fromhex(encrypted_value), None)
    return decrypted.decode()

def process_csv(input_csv, encrypted_csv, decrypted_csv, key):
    """Encrypt and decrypt a CSV dataset."""
    nonce = os.urandom(12)  # Generate a unique nonce for encryption
    
    with open(input_csv, 'r') as infile, \
         open(encrypted_csv, 'w', newline='') as encfile, \
         open(decrypted_csv, 'w', newline='') as decfile:

        reader = csv.reader(infile)
        enc_writer = csv.writer(encfile)
        dec_writer = csv.writer(decfile)

        headers = next(reader)
        enc_writer.writerow(headers)
        dec_writer.writerow(headers)

        for row in reader:
            # Encrypt each cell
            encrypted_row = [encrypt_value(cell, key, nonce) for cell in row]
            # Decrypt each cell
            decrypted_row = [decrypt_value(cell, key, nonce) for cell in encrypted_row]

            enc_writer.writerow(encrypted_row)
            dec_writer.writerow(decrypted_row)

if __name__ == "__main__":
    # Define file paths
    input_csv = 'healthcare_iot_data.csv'
    encrypted_csv = 'healthcare_iot_encrypted.csv'
    decrypted_csv = 'healthcare_iot_decrypted.csv'

    # Generate a 256-bit (32 bytes) key for ChaCha20-Poly1305
    key = os.urandom(32)  # This should be securely stored in a real-world scenario

    # Create a sample dataset if it doesn't exist
    if not os.path.exists(input_csv):
        with open(input_csv, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['DeviceID', 'HeartRate', 'Temperature', 'OxygenLevel'])
            writer.writerow(['Device001', '72', '36.7', '98'])
            writer.writerow(['Device002', '85', '37.1', '95'])
            writer.writerow(['Device003', '68', '36.5', '99'])

    print("Processing the IoT dataset...")
    process_csv(input_csv, encrypted_csv, decrypted_csv, key)
    print(f"Encryption and decryption completed!")
    print(f"Encrypted data saved to: {encrypted_csv}")
    print(f"Decrypted data saved to: {decrypted_csv}")
