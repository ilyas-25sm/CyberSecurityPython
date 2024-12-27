import pyinstaller_versionfile

# Настройка информации о версии антивируса "Mirza"
pyinstaller_versionfile.create_versionfile(
    output_file="versionfile.txt",
    version='1.0.0',  # Версия антивируса "Mirza"
    company_name="Mirza Security",
    file_description="Mirza Antivirus Software",
    internal_name="Mirza",
    legal_copyright="Mirza Security",
    original_filename="Mirza.exe",
    product_name="Mirza"
)
