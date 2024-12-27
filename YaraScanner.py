import os
import yara
import hashlib
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, filename="yara_scanner.log", filemode="a")

class YaraScanner:
    def __init__(self, rule_path='C:/Program Files/Mirza/yara', sigs_path='C:/Program Files/Mirza/sigs'):
        """
        Initialize YaraScanner with paths to rules and signature files.
        """
        self.rule_path = rule_path
        self.sigs_path = sigs_path
        os.makedirs(sigs_path, exist_ok=True)

        # Load and compile YARA rules during initialization
        self.rules = self.load_yara_rules()

    def load_yara_rules(self):
        """
        Load and compile YARA rules from the rule directory.
        """
        try:
            rule_files = {f: os.path.join(self.rule_path, f) for f in os.listdir(self.rule_path) if f.endswith('.yar')}
            return yara.compile(filepaths=rule_files, externals={
                'filepath': '',
                'filename': '',
                'extension': '',
                'filetype': '',
                'md5': '',
                'owner': '',
            })
        except yara.Error as e:
            logging.error(f"Error loading YARA rules: {e}")
            return None

    def generate_signature(self, file_path):
        """
        Generate a unique signature for a file and save it in YARA format.
        """
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.md5(file_data).hexdigest()
                sig_filename = os.path.join(self.sigs_path, f"{file_hash}.yar")

                yara_rule = f"""
rule File_{file_hash} {{
    meta:
        description = "Generated rule for file {file_path}"
        hash = "{file_hash}"
    strings:
        $file_hash = "{file_hash}"
    condition:
        $file_hash
}}
"""
                with open(sig_filename, "w") as sig_file:
                    sig_file.write(yara_rule)

                logging.info(f"Signature created for file {file_path} and saved as {sig_filename}")
                return sig_filename
        except Exception as e:
            logging.error(f"Error generating signature for {file_path}: {e}")
            return None

    def scan_file(self, file_path):
        """
        Scan a single file using YARA rules.
        """
        try:
            matches = self.rules.match(file_path, externals={
                'filepath': file_path,
                'filename': os.path.basename(file_path),
                'extension': os.path.splitext(file_path)[1],
                'filetype': 'unknown',
                'md5': self.calculate_md5(file_path),
                'owner': os.getlogin(),
            })

            if matches:
                logging.info(f"Match found for {file_path}: {matches}")
                return matches
            else:
                logging.info(f"No match found for {file_path}.")
            return None
        except yara.Error as e:
            logging.error(f"YARA scan error for {file_path}: {e}")
            return None

    def scan_directory(self, directory_path):
        """
        Scan all files in a directory using YARA rules.
        """
        hit_files = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                matches = self.scan_file(file_path)
                if matches:
                    hit_files.append((file_path, matches))
        return hit_files

    @staticmethod
    def calculate_md5(file_path):
        """
        Calculate the MD5 hash of a file.
        """
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            return None
        except Exception as e:
            logging.error(f"Error calculating MD5 for {file_path}: {e}")
            return None
