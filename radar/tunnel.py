"""
Модуль управления фоновым SSH-туннелем к панели 3x-ui (Smart Tunnel Manager).
Позволяет поднимать, отслеживать статус и безопасно завершать туннель в Windows.
"""

import subprocess
import socket
import time
import webbrowser
import os
from typing import Tuple, Optional

from radar.config import (
    DEFAULT_VPS_IP,
    DEFAULT_PANEL_LOCAL_PORT,
    DEFAULT_PANEL_PATH,
    DEFAULT_SSH_PORT
)

class TunnelManager:
    """Управление безопасным пробросом портов панели 3x-ui через SSH"""

    def __init__(
        self,
        vps_ip: str = DEFAULT_VPS_IP,
        panel_port: int = DEFAULT_PANEL_LOCAL_PORT,
        panel_path: str = DEFAULT_PANEL_PATH,
        ssh_port: int = DEFAULT_SSH_PORT,
        ssh_user: str = "root"
    ):
        self.vps_ip = vps_ip
        self.panel_port = panel_port
        self.panel_path = panel_path
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user

    def is_tunnel_active(self) -> bool:
        """Проверяет, слушает ли локальный порт 5541 входящие соединения"""
        try:
            with socket.create_connection(("127.0.0.1", self.panel_port), timeout=1.0):
                return True
        except Exception:
            return False

    def get_panel_url(self) -> str:
        """Возвращает полный локальный URL для входа в панель"""
        clean_path = self.panel_path.strip("/")
        return f"http://127.0.0.1:{self.panel_port}/{clean_path}/"

    def start_tunnel(self, open_browser: bool = True) -> Tuple[bool, str]:
        """
        Запускает фоновый процесс SSH для проброса порта 5541:
        ssh -N -L 5541:127.0.0.1:5541 root@<VPS_IP>
        """
        if self.is_tunnel_active():
            msg = "Туннель уже активен и слушает порт 5541."
            if open_browser:
                self.open_browser()
            return True, msg

        cmd = [
            "ssh",
            "-N",  # Не выполнять удалённые команды (только форвардинг)
            "-L", f"{self.panel_port}:127.0.0.1:{self.panel_port}",
            "-p", str(self.ssh_port),
            f"{self.ssh_user}@{self.vps_ip}"
        ]

        try:
            # В Windows запускаем процесс в отдельной фоновой группе (DETACHED_PROCESS)
            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS

            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags
            )

            # Ожидаем инициализации сокета туннеля (до 3 секунд)
            for _ in range(6):
                time.sleep(0.5)
                if self.is_tunnel_active():
                    if open_browser:
                        self.open_browser()
                    return True, f"Туннель успешно поднят! Панель доступна на {self.get_panel_url()}"

            return False, "Процесс SSH запущен, но порт 5541 пока не отвечает. Проверьте пароль или ключ SSH."

        except Exception as e:
            return False, f"Ошибка при запуске SSH-туннеля: {str(e)}"

    def stop_tunnel(self) -> Tuple[bool, str]:
        """Завершает фоновый процесс SSH, слушающий порт 5541"""
        if not self.is_tunnel_active():
            return True, "Туннель уже отключён."

        try:
            # Находим и завершаем процессы ssh.exe через taskkill в Windows
            if os.name == "nt":
                # Убиваем только процессы ssh.exe, поднятые для форвардинга
                cmd = ["taskkill", "/F", "/IM", "ssh.exe"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                time.sleep(0.5)
                if not self.is_tunnel_active():
                    return True, "Туннель успешно остановлен."
                return False, f"Не удалось завершить туннель: {res.stderr}"
            else:
                os.system(f"fuser -k {self.panel_port}/tcp")
                return True, "Туннель остановлен."
        except Exception as e:
            return False, f"Ошибка при остановке туннеля: {str(e)}"

    def open_browser(self):
        """Открывает страницу админки 3x-ui в браузере по умолчанию"""
        url = self.get_panel_url()
        webbrowser.open(url)
