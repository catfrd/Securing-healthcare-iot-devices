import csv
import secrets

class HIGHT:
    def __init__(self, key=None):
        self.key = key or self.generate_random_key()
        self.round_keys = self.key_expansion(self.key)

    @staticmethod
    def generate_random_key():
        """ Generate a random 128-bit key """
        return int.from_bytes(secrets.token_bytes(16), byteorder='big')  # 16 bytes = 128 bits

    def key_expansion(self, key):
        round_keys = []
        key_parts = [key >> (96 - 32 * i) & 0xFFFFFFFF for i in range(4)]  # Split key into 4 parts
        for i in range(32):
            round_keys.append(key_parts[i % 4])
        return round_keys

    def left_rotate(self, x, n):
        return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

    def sbox(self, x):
        sbox_table = [0x1, 0x7, 0x3, 0xF, 0xD, 0xB, 0x9, 0x5, 0xE, 0xA, 0x6, 0x2, 0xC, 0x8, 0x4, 0x0]
        return sbox_table[x]

    def f_function(self, x, k):
        sbox_output = sum([self.sbox((x >> (60 - 4 * i)) & 0xF) << (60 - 4 * i) for i in range(16)])
        return (sbox_output + k) & 0xFFFFFFFFFFFFFFFF  # Add round key and ensure 64-bit output

    def encrypt(self, plaintext):
        L, R = plaintext >> 32, plaintext & 0xFFFFFFFF
        for i in range(32):
            round_key = self.round_keys[i]
            f = self.f_function(R, round_key)
            R, L = (L ^ f) & 0xFFFFFFFF, (R + (f >> 32)) & 0xFFFFFFFF
        return (L << 32) | R

    def decrypt(self, ciphertext):
        L, R = ciphertext >> 32, ciphertext & 0xFFFFFFFF
        for i in range(31, -1, -1):
            round_key = self.round_keys[i]
            f = self.f_function(R, round_key)
            R, L = (L - (f >> 32)) & 0xFFFFFFFF, (R ^ f) & 0xFFFFFFFF
        return (L << 32) | R


def process_csv(input_file, encrypted_file, decrypted_file, cipher):
    """ Encrypt and decrypt CSV data """
    with open(input_file, 'r') as infile, \
         open(encrypted_file, 'w', newline='') as encfile, \
         open(decrypted_file, 'w', newline='') as decfile:

        reader = csv.reader(infile)
        enc_writer = csv.writer(encfile)
        dec_writer = csv.writer(decfile)

        # Write encrypted and decrypted headers
        headers = next(reader)
        enc_writer.writerow(headers)
        dec_writer.writerow(headers)

        for row in reader:
            encrypted_row = []
            decrypted_row = []

            for value in row:
                # Encrypt and decrypt each value (convert strings to numbers if needed)
                plaintext = int(value) if value.isdigit() else int.from_bytes(value.encode(), byteorder='big')
                encrypted_value = cipher.encrypt(plaintext)
                decrypted_value = cipher.decrypt(encrypted_value)

                # Convert back to readable formats
                encrypted_row.append(encrypted_value)
                decrypted_row.append(str(decrypted_value))

            enc_writer.writerow(encrypted_row)
            dec_writer.writerow(decrypted_row)


# Example Usage
cipher = HIGHT()
print(f"Generated Random Key: {hex(cipher.key)}")

# Input and output file paths
input_csv = '..\cryptography project\healthcare_iot_dataset.csv'  # Input CSV file with plaintext data
encrypted_csv = 'encrypted.csv'  # Output CSV file with encrypted data
decrypted_csv = 'decrypted.csv'  # Output CSV file with decrypted data

# Process CSV files
process_csv(input_csv, encrypted_csv, decrypted_csv, cipher)
print(f"Processing complete. Encrypted data saved to {encrypted_csv}, decrypted data saved to {decrypted_csv}.")
