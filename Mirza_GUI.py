import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QTabWidget, QAction, QComboBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from Mirza_Language import translate_dict  # Import translations

class AntivirusGUI(QMainWindow):
    def __init__(self, current_language="en_US"):
        super().__init__()
        self.current_language = current_language  # Set the current language
        self.init_ui()  # Initialize UI components

    def init_ui(self):
        # Set window title and geometry
        self.setWindowTitle(translate_dict[self.current_language].get("設置", "Mirza Antivirus"))
        self.setGeometry(100, 100, 800, 600)

        # Create menu bar
        menubar = self.menuBar()

        # Create File and Settings menus with translated titles
        self.file_menu = menubar.addMenu(translate_dict[self.current_language].get("文件", "File"))
        self.settings_menu = menubar.addMenu(translate_dict[self.current_language].get("設置", "Settings"))

        # Exit action for File menu
        self.exit_action = QAction(translate_dict[self.current_language].get("退出", "Exit"), self)
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)


        # Status bar with translated text
        self.statusBar().showMessage(translate_dict[self.current_language].get("狀態", "Status: Protected"))

        # Create the tab widget and add translated tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_scan_tab(), translate_dict[self.current_language].get("掃描", "Scan"))
        self.tabs.addTab(self.create_quarantine_tab(), translate_dict[self.current_language].get("隔離區", "Quarantine"))
        self.tabs.addTab(self.create_settings_tab(), translate_dict[self.current_language].get("設置", "Settings"))
        self.tabs.addTab(self.create_logs_tab(), translate_dict[self.current_language].get("日誌", "Logs"))

        # Set the tabs as the central widget of the window
        self.setCentralWidget(self.tabs)

    def create_scan_tab(self):
        """Create the Scan tab with translated buttons and labels."""
        scan_tab = QWidget()
        layout = QVBoxLayout()

        # Add status label with translation
        self.scan_status = QLabel(translate_dict[self.current_language].get("狀態", "System Status: Protected"))
        self.scan_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.scan_status)

        # Add scan buttons with translated text
        self.quick_scan_btn = QPushButton(translate_dict[self.current_language].get("快速掃描", "Quick Scan"))
        self.full_scan_btn = QPushButton(translate_dict[self.current_language].get("全盤掃描", "Full Scan"))
        self.single_file_scan_btn = QPushButton(translate_dict[self.current_language].get("單檔掃描", "Single File Scan"))

        # Add buttons to the layout
        layout.addWidget(self.quick_scan_btn)
        layout.addWidget(self.full_scan_btn)
        layout.addWidget(self.single_file_scan_btn)

        # Set layout to the tab
        scan_tab.setLayout(layout)
        return scan_tab

    def create_quarantine_tab(self):
        """Create the Quarantine tab."""
        quarantine_tab = QWidget()
        layout = QVBoxLayout()

        # Add quarantine label with translation
        quarantine_label = QLabel(translate_dict[self.current_language].get("隔離區", "Quarantine - No threats detected"))
        quarantine_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(quarantine_label)

        # Set layout to the tab
        quarantine_tab.setLayout(layout)
        return quarantine_tab

    def create_settings_tab(self):
        """Create the Settings tab."""
        settings_tab = QWidget()
        layout = QVBoxLayout()

        # Add settings label with translation
        settings_label = QLabel(translate_dict[self.current_language].get("設置", "Settings"))
        settings_label.setAlignment(Qt.AlignCenter)

        # Add the language combo box to the Settings tab
        self.language_combo = QComboBox(self)
        self.language_combo.addItem("English", "en_US")
        self.language_combo.addItem("Русский", "ru_RU")
        self.language_combo.addItem("Қазақ", "kk_KZ")
        self.language_combo.activated[str].connect(self.change_language)

        # Add button to update virus definitions with translation
        update_btn = QPushButton(translate_dict[self.current_language].get("更新病毒定義", "Update Virus Definitions"))
        update_btn.clicked.connect(lambda: print(translate_dict[self.current_language].get("更新病毒定義", "Updating virus definitions...")))

        # Add elements to the layout
        layout.addWidget(settings_label)
        layout.addWidget(self.language_combo)
        layout.addWidget(update_btn)

        # Set layout to the tab
        settings_tab.setLayout(layout)
        return settings_tab

    def create_logs_tab(self):
        """Create the Logs tab."""
        logs_tab = QWidget()
        layout = QVBoxLayout()

        # Add logs label with translation
        log_label = QLabel(translate_dict[self.current_language].get("日誌", "Logs - No events recorded"))
        log_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(log_label)

        # Set layout to the tab
        logs_tab.setLayout(layout)
        return logs_tab

    def open_settings(self):
        """Open the settings dialog."""
        print(translate_dict[self.current_language].get("設置", "Settings"))

    def change_language(self, lang_code):
        """Change the application language."""
        self.current_language = self.language_combo.currentData()
        self.update_translations()

    def update_translations(self):
        """Update the UI with translations when the language changes."""
        # Update window title and menu bar
        self.setWindowTitle(translate_dict[self.current_language].get("設置", "Mirza Antivirus"))
        self.file_menu.setTitle(translate_dict[self.current_language].get("文件", "File"))
        self.settings_menu.setTitle(translate_dict[self.current_language].get("設置", "Settings"))

        # Update menu actions
        self.exit_action.setText(translate_dict[self.current_language].get("退出", "Exit"))
        self.settings_action.setText(translate_dict[self.current_language].get("設置", "Settings"))

        # Update tab titles
        self.tabs.setTabText(0, translate_dict[self.current_language].get("掃描", "Scan"))
        self.tabs.setTabText(1, translate_dict[self.current_language].get("隔離區", "Quarantine"))
        self.tabs.setTabText(2, translate_dict[self.current_language].get("設置", "Settings"))
        self.tabs.setTabText(3, translate_dict[self.current_language].get("日誌", "Logs"))

        # Update status message and scan tab button text
        self.scan_status.setText(translate_dict[self.current_language].get("狀態", "System Status: Protected"))
        self.quick_scan_btn.setText(translate_dict[self.current_language].get("快速掃描", "Quick Scan"))
        self.full_scan_btn.setText(translate_dict[self.current_language].get("全盤掃描", "Full Scan"))
        self.single_file_scan_btn.setText(translate_dict[self.current_language].get("單檔掃描", "Single File Scan"))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntivirusGUI(current_language="en_US")  # Default language is English
    window.show()
    sys.exit(app.exec_())
