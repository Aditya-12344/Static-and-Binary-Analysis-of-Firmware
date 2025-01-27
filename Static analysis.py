import os
import binwalk
import hashlib
import magic
import re

def extract_firmware(binary_file):
    """
    Extracts the firmware from the given binary file using binwalk.
    """
    extracted_folder = binary_file + '_extracted'
    os.makedirs(extracted_folder, exist_ok=True)

    # Run binwalk to extract the firmware
    os.system(f'binwalk -e {binary_file} -C {extracted_folder}')

    return extracted_folder

def analyze_firmware(extracted_folder):
    """
    Analyzes the extracted firmware and generates a report.
    """
    report = ""

    # Generate file structure report (tree structure)
    report += "# Directory Tree Structure\n"
    report += generate_directory_tree(extracted_folder)

    # Analyze firmware files and generate detailed report
    firmware_details = analyze_firmware_files(extracted_folder)
    report += "\n# Firmware Details\n"
    for key, value in firmware_details.items():
        report += f"{key}: {value}\n"

    # Analyze security details
    report += "\n# Security Details\n"
    security_details = analyze_security(extracted_folder)
    for key, value in security_details.items():
        report += f"{key}: {value}\n"

    return report

def generate_directory_tree(extracted_folder):
    """
    Generates the directory tree structure of the extracted firmware.
    """
    tree_structure = ""

    for root, dirs, files in os.walk(extracted_folder):
        indent = '--- ' * (root.count(os.sep) - extracted_folder.count(os.sep))
        tree_structure += f"{indent}{os.path.basename(root)}\n"
        for file in files:
            file_path = os.path.join(root, file)
            file_type = magic.from_file(file_path)
            tree_structure += f"{indent}--- {file} [{file_type}]\n"

    return tree_structure

def analyze_firmware_files(extracted_folder):
    """
    Analyzes various metrics of the extracted firmware files.
    """
    firmware_details = {}

    for root, dirs, files in os.walk(extracted_folder):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            md5_hash = calculate_md5(file_path)
            file_format = magic.from_file(file_path)
            detected_urls = extract_urls(file_path)
            detected_ips = extract_ips(file_path)
            entropy_value = calculate_entropy(file_path)

            # Add extracted data to report
            firmware_details[file] = {
                "File Size": file_size,
                "MD5 Hash": md5_hash,
                "File Format": file_format,
                "Detected URLs": detected_urls,
                "Detected IP Addresses": detected_ips,
                "Entropy": entropy_value
            }

    return firmware_details

def calculate_md5(file_path):
    """
    Calculates the MD5 hash of the file.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def extract_urls(file_path):
    """
    Extracts URLs from the file using regex.
    """
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    urls = re.findall(r'(https?://[^\s]+)', content)
    return urls

def extract_ips(file_path):
    """
    Extracts IP addresses from the file using regex.
    """
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
    return ips

def calculate_entropy(file_path):
    """
    Calculates the entropy of the file.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1

    entropy = 0.0
    for freq in byte_freq:
        if freq > 0:
            p = freq / len(data)
            entropy -= p * (p).bit_length()

    return entropy

def analyze_security(extracted_folder):
    """
    Analyzes security-related files like etc/shadow, etc/passwd, etc.
    """
    security_details = {
        "etc/shadow and etc/passwd files": "",
        "List of etc/ssl directory files": [],
        "SSL related files": [],
        "Configuration files": [],
        "Script files": [],
        "Other .bin files": [],
        "Keywords found": []
    }

    for root, dirs, files in os.walk(extracted_folder):
        for file in files:
            file_path = os.path.join(root, file)

            if 'etc/shadow' in file or 'etc/passwd' in file:
                with open(file_path, 'r', errors='ignore') as f:
                    security_details["etc/shadow and etc/passwd files"] += f.read()

            if 'etc/ssl' in file:
                security_details["List of etc/ssl directory files"].append(file)

            if file.endswith(('.pem', '.crt')):
                security_details["SSL related files"].append(file)

            if file.endswith(('.conf', '.config')):
                security_details["Configuration files"].append(file)

            if file.endswith(('.sh', '.bash', '.py')):
                security_details["Script files"].append(file)

            if file.endswith('.bin'):
                security_details["Other .bin files"].append(file)

            # Searching for common keywords related to vulnerabilities
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                keywords = ["password", "root", "admin", "vulnerable", "exploit"]
                for keyword in keywords:
                    if keyword in content:
                        security_details["Keywords found"].append(keyword)

    return security_details

def main():
    # Take the filename input from the user
    binary_file = input("Enter the firmware binary file name (including extension): ")

    if not os.path.isfile(binary_file):
        print(f"File {binary_file} not found in the current directory.")
        return

    # Extract the firmware
    extracted_folder = extract_firmware(binary_file)

    # Analyze the firmware and generate the report
    report = analyze_firmware(extracted_folder)

    # Save the report to a markdown file
    with open('firmware_analysis_report.md', 'w') as f:
        f.write(report)

    print("Analysis complete! Report generated: firmware_analysis_report.md")

if __name__ == "__main__":
    main()
