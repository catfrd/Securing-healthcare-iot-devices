from ascon import Ascon128
import csv
import os

# ASCON parameters
KEY = os.urandom(16)  # 128-bit key
NONCE = os.urandom(16)  # 128-bit nonce (must be unique for each encryption)

def encrypt_value(value, key, nonce):
    """Encrypt a string value using ASCON."""
    cipher = Ascon128(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(value.encode())
    return ciphertext.hex()

def decrypt_value(encrypted_value, key, nonce):
    """Decrypt a string value using ASCON."""
    cipher = Ascon128(key=key, nonce=nonce)
    plaintext = cipher.decrypt(bytes.fromhex(encrypted_value))
    return plaintext.decode()

def process_csv(input_csv, encrypted_csv, decrypted_csv, key, nonce):
    """Encrypt and decrypt a CSV dataset using ASCON."""
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
            encrypted_row = [encrypt_value(cell, key, nonce) for cell in row]
            decrypted_row = [decrypt_value(cell, key, nonce) for cell in encrypted_row]

            enc_writer.writerow(encrypted_row)
            dec_writer.writerow(decrypted_row)

if __name__ == "__main__":
    # Define file paths
    input_csv = 'healthcare_iot_data.csv'
    encrypted_csv = 'healthcare_iot_ascon_encrypted.csv'
    decrypted_csv = 'healthcare_iot_ascon_decrypted.csv'

    # Create a sample dataset if it doesn't exist
    if not os.path.exists(input_csv):
        with open(input_csv, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['DeviceID', 'HeartRate', 'Temperature', 'OxygenLevel'])
            writer.writerow(['Device001', '72', '36.7', '98'])
            writer.writerow(['Device002', '85', '37.1', '95'])
            writer.writerow(['Device003', '68', '36.5', '99'])

    print("Processing the IoT dataset with ASCON...")
    process_csv(input_csv, encrypted_csv, decrypted_csv, KEY, NONCE)
    print(f"Encryption and decryption completed!")
    print(f"Encrypted data saved to: {encrypted_csv}")
    print(f"Decrypted data saved to: {decrypted_csv}")
