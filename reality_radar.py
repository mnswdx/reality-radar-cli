#!/usr/bin/env python3
"""
Reality Radar & Sentinel CLI
Главная точка входа для запуска аудита REALITY, сканера доноров и туннелей.
"""

import sys
import os

# Принудительно включаем UTF-8 кодировку для консоли Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    # Включаем поддержку ANSI escape-последовательностей в Windows 10/11
    os.system("")

# Добавляем текущую директорию в PYTHONPATH для корректного импорта пакета radar
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from radar.cli import main

if __name__ == "__main__":
    main()
