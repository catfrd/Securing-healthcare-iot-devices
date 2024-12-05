import struct
import csv
import os

def xtea_encrypt(key, block, num_rounds=32):
    """Encrypts a single block of data using the XTEA algorithm."""
    v0, v1 = struct.unpack(">2L", block)
    sum = 0
    delta = 0x9E3779B9

    for _ in range(num_rounds):
        v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3])
        v0 &= 0xFFFFFFFF
        sum += delta
        sum &= 0xFFFFFFFF
        v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum >> 11 & 3])
        v1 &= 0xFFFFFFFF

    return struct.pack(">2L", v0, v1)

def xtea_decrypt(key, block, num_rounds=32):
    """Decrypts a single block of data using the XTEA algorithm."""
    v0, v1 = struct.unpack(">2L", block)
    delta = 0x9E3779B9
    sum = (delta * num_rounds) & 0xFFFFFFFF

    for _ in range(num_rounds):
        v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum >> 11 & 3])
        v1 &= 0xFFFFFFFF
        sum -= delta
        sum &= 0xFFFFFFFF
        v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3])
        v0 &= 0xFFFFFFFF

    return struct.pack(">2L", v0, v1)

def prepare_key(raw_key):
    """Prepare a 16-byte key for use with the XTEA algorithm."""
    return struct.unpack(">4L", raw_key)

def pad(value):
    """Pads the value to a multiple of 8 bytes."""
    while len(value) % 8 != 0:
        value += " "
    return value

def unpad(value):
    """Removes padding from the value."""
    return value.rstrip()

def encrypt_value(value, key):
    """Encrypt a string value."""
    padded_value = pad(value).encode()
    encrypted_blocks = [
        xtea_encrypt(key, padded_value[i:i+8])
        for i in range(0, len(padded_value), 8)
    ]
    return b"".join(encrypted_blocks).hex()

def decrypt_value(encrypted_value, key):
    """Decrypt a string value."""
    encrypted_bytes = bytes.fromhex(encrypted_value)
    decrypted_blocks = [
        xtea_decrypt(key, encrypted_bytes[i:i+8])
        for i in range(0, len(encrypted_bytes), 8)
    ]
    decrypted_data = b"".join(decrypted_blocks)
    return unpad(decrypted_data.decode())

def process_csv(input_csv, encrypted_csv, decrypted_csv, key):
    """Encrypt and decrypt a CSV dataset."""
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
            encrypted_row = [encrypt_value(cell, key) for cell in row]
            decrypted_row = [decrypt_value(cell, key) for cell in encrypted_row]

            enc_writer.writerow(encrypted_row)
            dec_writer.writerow(decrypted_row)

if __name__ == "__main__":

    input_csv = 'healthcare_iot_data.csv'
    encrypted_csv = 'iot_data_encrypted.csv'
    decrypted_csv = 'iot_data_decrypted.csv'

    raw_key = os.urandom(16)
    XTEA_KEY = prepare_key(raw_key)

    if not os.path.exists(input_csv):
        with open(input_csv, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['DeviceID', 'Temperature', 'HeartRate'])
            writer.writerow(['001', '36.6', '78'])
            writer.writerow(['002', '37.1', '82'])
            writer.writerow(['003', '36.4', '75'])

    print("Processing the IoT dataset...")
    process_csv(input_csv, encrypted_csv, decrypted_csv, XTEA_KEY)
    print("Encryption and decryption completed!")
    print(f"Encrypted data saved to: {encrypted_csv}")
    print(f"Decrypted data saved to: {decrypted_csv}")
