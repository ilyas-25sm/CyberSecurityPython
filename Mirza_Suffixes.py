# Списки файловых суффиксов для проверки антивирусом "Mirza"

# Список файловых суффиксов, которые всегда должны проверяться (приоритетные)
HIGH_PRIORITY_SUFFIXES = [
    ".exe", ".dll", ".sys", ".com", ".scr",
    ".bat", ".ps1", ".vbs", ".cmd", ".js"
]

# Расширенный список файловых суффиксов для сканирования
EXTENDED_SUFFIXES = [
    # Исполняемые файлы
    ".exe", ".dll", ".sys", ".com", ".scr",

    # Архивы и сжатые файлы
    ".zip", ".7z", ".rar", ".tar", ".gz",

    # Скрипты
    ".js", ".bat", ".cmd", ".ps1", ".vbs",

    # Документы
    ".ppt", ".pptx", ".wps", ".txt", ".rtf", ".pdf",
    ".xls", ".xlsx", ".doc", ".docx",

    # Изображения
    ".jpg", ".jpeg", ".png", ".webp", ".gif",

    # Аудиофайлы
    ".mp3", ".wav", ".aac", ".ogg", ".flac",

    # Видеофайлы
    ".mp4", ".avi", ".mov", ".wmv", ".mkv",

    # Системные файлы
    ".aux", ".cur", ".mui", ".ttf", ".efi"
]


def should_scan_file(extension, use_extended=False):
    """
    Проверяет, должен ли файл с данным расширением быть отсканирован антивирусом.

    Args:
        extension (str): Расширение файла, например, ".exe".
        use_extended (bool): Если True, используется расширенный список (EXTENDED_SUFFIXES).

    Returns:
        bool: True, если файл должен быть отсканирован, иначе False.
    """
    if use_extended:
        return extension.lower() in EXTENDED_SUFFIXES
    return extension.lower() in HIGH_PRIORITY_SUFFIXES


def list_supported_suffixes(use_extended=False):
    """
    Возвращает список всех поддерживаемых суффиксов для сканирования.

    Args:
        use_extended (bool): Если True, возвращает расширенный список (EXTENDED_SUFFIXES).

    Returns:
        list: Список поддерживаемых суффиксов.
    """
    return EXTENDED_SUFFIXES if use_extended else HIGH_PRIORITY_SUFFIXES


# MAIN (Для тестирования модуля)
if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)

    # Тестирование суффиксов
    test_suffixes = [".exe", ".mp3", ".unknown", ".pdf"]
    for suffix in test_suffixes:
        logging.info(
            f"Should scan {suffix} (High Priority): {should_scan_file(suffix)}"
        )
        logging.info(
            f"Should scan {suffix} (Extended): {should_scan_file(suffix, use_extended=True)}"
        )

    # Вывод всех поддерживаемых суффиксов
    logging.info(f"High Priority Suffixes: {list_supported_suffixes()}")
    logging.info(f"Extended Suffixes: {list_supported_suffixes(use_extended=True)}")
