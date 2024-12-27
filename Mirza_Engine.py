import os
import json
import yara
import numpy as np
import pefile
import onnxruntime
import hashlib
import sqlite3
from PIL import Image
from YaraScanner import YaraScanner  # Import YARA scanning
from datetime import datetime

class MirzaYRScan:
    def __init__(self):
        """Initialize YARA scanner."""
        self.yara_scanner = YaraScanner()

    def scan(self, file_path):
        """Scan a file with YARA rules."""
        matches = self.yara_scanner.scan_file(file_path)
        if matches:
            return True, matches
        return False, []

class MirzaDLScan:
    def __init__(self):
        """Initialize Deep Learning (DL) scanner."""
        self.models = {}
        self.detect = []
        self.class_names = {}
        self.values = 100
        self.shells = ['!o', '/4', '0a@', '_test', 'ace', 'yg', 'engine', 'extjmp', 'lzmadec', 'packer', 'upx', 'vmp', 'wow64svc']

    def load_model(self, file_path):
        """Load a deep learning model for malware detection."""
        try:
            extension = f".{file_path.split('.')[-1]}".lower()
            if extension in [".json", ".txt"]:
                with open(file_path, 'r') as f:
                    self.class_names = json.load(f)
            elif extension == ".onnx":
                self.models[file_path] = onnxruntime.InferenceSession(file_path)
            self.values = self.class_names.get('Values', 100)
            self.detect = self.class_names.get('Detect', [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading DL model: {e}")

    def predict(self, file_data):
        """Run prediction on file data using loaded models."""
        try:
            target_size = tuple(self.class_names.get('Pixels', (224, 224)))
            sim = {}
            image = self.preprocess_image(file_data, target_size)
            image_array = np.array(image).astype('float32') / 255.0
            image_expand = np.expand_dims(image_array, axis=0)
            for model_name, model in self.models.items():
                input_name = model.get_inputs()[0].name
                prediction = model.run(None, {input_name: image_expand})[0][0]
                label_index = np.argmax(prediction)
                label = self.class_names['Labels'][label_index].replace("\n", "")
                sim[label] = sim.get(label, 0) + prediction[label_index]
            for label, score in sim.items():
                if score > len(self.models) / 2:
                    return label, score * 100 / len(self.models)
            return False, False
        except Exception as e:
            print(f"Error during prediction: {e}")
            return False, False

    def scan(self, file_path):
        """Scan file with loaded deep learning models."""
        try:
            if isinstance(file_path, bytes):
                return self.predict(file_path)
            else:
                extension = f".{file_path.split('.')[-1]}".lower()
                if extension in [".exe", ".dll", ".sys"]:
                    with pefile.PE(file_path, fast_load=True) as pe:
                        data = [section.get_data() for section in pe.sections if section.Characteristics & 0x20000000 and
                                not any(shell in section.Name.decode().strip('\x00').lower() for shell in self.shells)]
                elif extension in [".bat", ".vbs", ".ps1"]:
                    with open(file_path, 'rb') as file:
                        data = [file.read()]
                for file_data in data:
                    label, score = self.predict(file_data)
                    if label and label in self.detect:
                        return label, score
            return False, False
        except (FileNotFoundError, pefile.PEFormatError) as e:
            print(f"Error during DL scan: {e}")
            return False, False

    @staticmethod
    def preprocess_image(file_data, target_size):
        """Convert binary file data to image format for model input."""
        file_data = np.frombuffer(file_data, dtype=np.uint8)
        image_side = int(np.ceil(np.sqrt((len(file_data) + 2) // 3)))
        image_array = np.zeros((image_side * image_side * 3,), dtype=np.uint8)
        image_array[:len(file_data)] = file_data
        image = Image.fromarray(image_array.reshape((image_side, image_side, 3)))
        return image.resize(target_size, Image.Resampling.LANCZOS)

class MirzaEngine:
    def __init__(self, db_file='C:/Program Files/Mirza/HashDB'):
        """Initialize the engine with paths for DB and YARA rules."""
        self.db_file = db_file
        self.yara_scan = MirzaYRScan()  # Use MirzaYRScan for YARA rules
        self.dl_scan = MirzaDLScan()   # Initialize DL scanner

    def create_connection(self):
        """Create a connection to the database and set up malware hash table."""
        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_hashes (
                hash TEXT PRIMARY KEY,
                name TEXT
            )
        ''')
        connection.commit()
        return connection

    def hash_check(self, file_path, db_connection):
        """Check file hash against malware hash database."""
        try:
            with open(file_path, 'rb') as file:
                file_hash = hashlib.md5(file.read()).hexdigest()
                cursor = db_connection.cursor()
                cursor.execute("SELECT name FROM malware_hashes WHERE hash=?", (file_hash,))
                result = cursor.fetchone()
                return f"Malware Detected: {result[0]}" if result else "File is clean"
        except Exception as e:
            print(f"Error during hash check: {e}")
            return "Error during hash check."

    def yara_check(self, file_path):
        """Run YARA scan on the specified file."""
        result, matches = self.yara_scan.scan(file_path)
        if result:
            return f"YARA Detection: {matches}"
        return "No YARA threats detected."

    def dl_check(self, file_path):
        """Run deep learning-based malware detection."""
        try:
            label, score = self.dl_scan.scan(file_path)
            if label:
                return f"DL Detection: {label} with confidence {score}%"
            return "No DL threats detected."
        except Exception as e:
            print(f"Error during DL check: {e}")
            return "Error during DL check."

    def quick_scan(self, directories):
        """Perform a quick scan on specified directories."""
        db_connection = self.create_connection()
        for directory in directories:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    hash_result = self.hash_check(file_path, db_connection)
                    yara_result = self.yara_check(file_path)
                    dl_result = self.dl_check(file_path)
                    print(f"{file_path} - {hash_result} - {yara_result} - {dl_result}")
        db_connection.close()

    def full_scan(self):
        """Perform a full system scan across all available drives."""
        drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        self.quick_scan(drives)
