import csv
import random

def generate_healthcare_iot_dataset(file_name, num_records=300):

    headers = ['DeviceID', 'PatientID', 'HeartRate (bpm)', 'Temperature (°C)', 'OxygenLevel (%)', 'Timestamp']

    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)

        for i in range(1, num_records + 1):
            device_id = f"{random.randint(1000, 9999)}"
            patient_id = f"{random.randint(100, 999)}"
            heart_rate = random.randint(60, 100)  # Normal range: 60-100 bpm
            temperature = round(random.uniform(36.0, 37.5), 1)  # Normal range: 36-37.5°C
            oxygen_level = random.randint(90, 100)  # Normal range: 90-100%
            timestamp = f"2024-12-{random.randint(1, 31):02d} {random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"

            writer.writerow([device_id, patient_id, heart_rate, temperature, oxygen_level, timestamp])

    print(f"Healthcare IoT dataset with {num_records} records saved to {file_name}.")

if __name__ == "__main__":
    generate_healthcare_iot_dataset("healthcare_iot_dataset.csv", 300)
