import os
import sys
import logging
from PyQt5.QtWidgets import (
    QApplication, QFileDialog, QMessageBox, QProgressBar, QLabel,
    QVBoxLayout, QWidget, QComboBox, QPushButton, QMainWindow, QRadioButton, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal
from Mirza_Engine import MirzaEngine
from YaraScanner import YaraScanner
from Mirza_Poly import PolymorphicVirusDetector
from Mirza_Firewall import start_firewall, FULL_ISOLATION, SELECTIVE_PROTECTION
from Mirza_Language import MirzaLanguage
from Mirza_RabbitMQ import RabbitMQMonitorThread

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class ScanThread(QThread):
    scan_complete = pyqtSignal()
    progress_update = pyqtSignal(int, str)

    def __init__(self, scan_func, directories):
        super().__init__()
        self.scan_func = scan_func
        self.directories = directories

    def run(self):
        total_files = sum(len(files) for directory in self.directories for _, _, files in os.walk(directory))
        scanned_files = 0

        for directory in self.directories:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    try:
                        self.scan_func(file_path)
                    except Exception as e:
                        logging.error(f"Error scanning file {file_path}: {e}")
                    progress = int((scanned_files / total_files) * 100)
                    self.progress_update.emit(progress, file_path)

        self.scan_complete.emit()


class MirzaAntivirus(QMainWindow):
    def __init__(self):
        super(MirzaAntivirus, self).__init__()
        self.current_language = "en_US"
        self.engine = MirzaEngine()
        self.yara_scanner = YaraScanner()
        self.poly_detector = PolymorphicVirusDetector()

        try:
            self.poly_detector.train_model()
        except Exception as e:
            logging.error(f"Error initializing polymorphic detector: {e}")

        self.rabbitmq_monitor = None
        self.firewall_mode = FULL_ISOLATION
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(MirzaLanguage.get_translation("title", self.current_language))
        self.setGeometry(100, 100, 800, 600)

        # Language selection
        self.language_combo = QComboBox(self)
        self.language_combo.addItem("English", "en_US")
        self.language_combo.addItem("Русский", "ru_RU")
        self.language_combo.addItem("Қазақ", "kk_KZ")
        self.language_combo.addItem("Chinese", "zh_TW")
        self.language_combo.currentIndexChanged.connect(self.change_language)

        # Progress indicators
        self.progress_bar = QProgressBar(self)
        self.file_label = QLabel(self)
        self.progress_bar.setVisible(False)
        self.file_label.setVisible(False)

        # Scan type radio buttons
        self.hash_scan_radio = QRadioButton(MirzaLanguage.get_translation("HASH_scan", self.current_language), self)
        self.yara_scan_radio = QRadioButton(MirzaLanguage.get_translation("YARA_scan", self.current_language), self)
        self.poly_scan_radio = QRadioButton(MirzaLanguage.get_translation("POLY_scan", self.current_language), self)
        self.hash_scan_radio.setChecked(True)

        # Firewall settings
        self.full_isolation_radio = QRadioButton(MirzaLanguage.get_translation("FULL_isolation", self.current_language), self)
        self.selective_protection_radio = QRadioButton(MirzaLanguage.get_translation("SELECTIVE_protection", self.current_language), self)
        self.full_isolation_radio.setChecked(True)

        firewall_layout = QHBoxLayout()
        firewall_layout.addWidget(self.full_isolation_radio)
        firewall_layout.addWidget(self.selective_protection_radio)

        self.full_isolation_radio.toggled.connect(self.set_firewall_mode)
        self.selective_protection_radio.toggled.connect(self.set_firewall_mode)

        self.firewall_status_label = QLabel(MirzaLanguage.get_translation("firewall_status", self.current_language), self)

        # Action buttons
        self.quick_scan_btn = QPushButton(MirzaLanguage.get_translation("quick_scan", self.current_language), self)
        self.full_scan_btn = QPushButton(MirzaLanguage.get_translation("full_scan", self.current_language), self)
        self.single_file_scan_btn = QPushButton(MirzaLanguage.get_translation("single_file_scan", self.current_language), self)
        self.quick_scan_btn.clicked.connect(self.start_quick_scan)
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        self.single_file_scan_btn.clicked.connect(self.single_file_scan)

        # RabbitMQ buttons
        self.rabbitmq_start_btn = QPushButton(MirzaLanguage.get_translation("Start_rabbitmq", self.current_language), self)
        self.rabbitmq_stop_btn = QPushButton(MirzaLanguage.get_translation("Stop_rabbitmq", self.current_language), self)
        self.rabbitmq_status_label = QLabel(MirzaLanguage.get_translation("Rabbitmq_status", self.current_language), self)
        self.rabbitmq_start_btn.clicked.connect(self.start_rabbitmq_monitoring)
        self.rabbitmq_stop_btn.clicked.connect(self.stop_rabbitmq_monitoring)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.language_combo)
        layout.addWidget(self.hash_scan_radio)
        layout.addWidget(self.yara_scan_radio)
        layout.addWidget(self.poly_scan_radio)
        layout.addLayout(firewall_layout)
        layout.addWidget(self.firewall_status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.file_label)
        layout.addWidget(self.quick_scan_btn)
        layout.addWidget(self.full_scan_btn)
        layout.addWidget(self.single_file_scan_btn)
        layout.addWidget(self.rabbitmq_start_btn)
        layout.addWidget(self.rabbitmq_stop_btn)
        layout.addWidget(self.rabbitmq_status_label)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def set_firewall_mode(self):
        if self.full_isolation_radio.isChecked():
            self.firewall_mode = FULL_ISOLATION
            self.firewall_status_label.setText(MirzaLanguage.get_translation("firewall_active", self.current_language))
        elif self.selective_protection_radio.isChecked():
            self.firewall_mode = SELECTIVE_PROTECTION
            self.firewall_status_label.setText(MirzaLanguage.get_translation("firewall_selective", self.current_language))
        start_firewall(self.firewall_mode)

    def start_rabbitmq_monitoring(self):
        if self.rabbitmq_monitor and self.rabbitmq_monitor.isRunning():
            QMessageBox.warning(self, "RabbitMQ Monitoring", "RabbitMQ is already running.")
            return

        self.rabbitmq_monitor = RabbitMQMonitorThread(host="localhost", queue="process_queue")
        self.rabbitmq_monitor.error_signal.connect(self.handle_rabbitmq_error)
        self.rabbitmq_monitor.start()
        self.rabbitmq_status_label.setText(MirzaLanguage.get_translation("rabbitmq_active", self.current_language))
        logging.info("RabbitMQ monitoring started.")

    def stop_rabbitmq_monitoring(self):
        if self.rabbitmq_monitor and self.rabbitmq_monitor.isRunning():
            self.rabbitmq_monitor.terminate()
            self.rabbitmq_monitor = None
            self.rabbitmq_status_label.setText(MirzaLanguage.get_translation("rabbitmq_stopped", self.current_language))
            logging.info("RabbitMQ monitoring stopped.")
        else:
            QMessageBox.warning(self, "RabbitMQ Monitoring", "RabbitMQ is not running.")

    def handle_rabbitmq_error(self, error_message):
        QMessageBox.critical(self, "RabbitMQ Monitoring Error", f"Error: {error_message}")

    def change_language(self):
        self.current_language = self.language_combo.currentData()
        self.init_ui()

    def start_quick_scan(self):
        directories = [os.path.expanduser("~/Desktop"), os.path.expanduser("~/Downloads")]
        self.start_scan(directories)

    def start_full_scan(self):
        drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        self.start_scan(drives)

    def single_file_scan(self):
        file_path = QFileDialog.getOpenFileName(self, MirzaLanguage.get_translation("select_file", self.current_language), "", "All Files (*)")[0]
        if file_path:
            try:
                result = self.get_scan_function()(file_path)
                QMessageBox.information(self, "Scan Result", result)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error scanning file: {e}")

    def start_scan(self, directories):
        self.progress_bar.setVisible(True)
        self.file_label.setVisible(True)

        scan_func = self.get_scan_function()
        self.scan_thread = ScanThread(scan_func, directories)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.scan_complete.connect(self.scan_complete)
        self.scan_thread.start()

    def get_scan_function(self):
        if self.hash_scan_radio.isChecked():
            return lambda file: self.engine.hash_check(file, self.engine.create_connection())
        elif self.yara_scan_radio.isChecked():
            return self.yara_scanner.scan_file
        elif self.poly_scan_radio.isChecked():
            return self.poly_detector.detect_polymorphic_virus

    def update_progress(self, progress, file_path):
        self.progress_bar.setValue(progress)
        self.file_label.setText(f"Scanning: {file_path}")

    def scan_complete(self):
        QMessageBox.information(self, "Scan Complete", "Scanning has completed successfully.")
        self.progress_bar.setVisible(False)
        self.file_label.setVisible(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MirzaAntivirus()
    window.show()
    sys.exit(app.exec())
