"""
Модуль конфигурации Reality Radar & Sentinel.
Содержит настройки по умолчанию, безопасную загрузку локального конфига и списки доноров.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
import os
import json

# Безопасные обезличенные значения по умолчанию для публичного репозитория GitHub
DEFAULT_VPS_IP = "127.0.0.1"
DEFAULT_VPS_PORT = 443
DEFAULT_SSH_PORT = 22
DEFAULT_PANEL_LOCAL_PORT = 5541
DEFAULT_PANEL_PATH = "/secret-path/"
DEFAULT_ACTIVE_DONOR = "speedtest.serverius.net"

# Список известных европейских и нидерландских доменов для глубокого сканирования
CURATED_CANDIDATES = [
    # Нидерландские хостинги, IX и дата-центры
    "speedtest.serverius.net",
    "ams-ix.net",
    "leaseweb.com",
    "nl-ix.net",
    "bit.nl",
    "transip.nl",
    "i3d.net",
    "hostnet.nl",
    
    # Европейские зеркала дистрибутивов и открытого ПО
    "ftp.nluug.nl",
    "mirror.ams1.nl.leaseweb.net",
    "nl.alpinelinux.org",
    "archlinux.mirror.wearetriple.com",
    "mirror.cj2.nl",
    
    # Университеты и научные центры Нидерландов
    "tudelft.nl",
    "uva.nl",
    "vu.nl",
    "uu.nl",
    "rug.nl",
    "tue.nl",
    
    # Популярные европейские нейтральные сервисы
    "debian.org",
    "kernel.org",
    "videolan.org",
    "mozilla.org",
    "libreoffice.org",
    "kde.org",
    "archlinux.org",
    "alpinelinux.org"
]

# Сигнатуры известных CDN, не подходящих для прямого VLESS-REALITY
KNOWN_CDN_HEADERS = [
    "cf-ray",
    "cloudflare",
    "akamai",
    "fastly",
    "incap-ses",
    "x-amz-cf-id",
    "x-sucuri-id",
    "varnish"
]

@dataclass
class RadarConfig:
    """Конфигурация сканера и мониторинга"""
    vps_ip: str = DEFAULT_VPS_IP
    vps_port: int = DEFAULT_VPS_PORT
    ssh_port: int = DEFAULT_SSH_PORT
    panel_local_port: int = DEFAULT_PANEL_LOCAL_PORT
    panel_path: str = DEFAULT_PANEL_PATH
    active_donor: str = DEFAULT_ACTIVE_DONOR
    timeout: float = 4.0
    threads: int = 10
    candidates: List[str] = field(default_factory=lambda: list(CURATED_CANDIDATES))

    def __post_init__(self):
        """Загрузка приватных настроек из локального файла config.local.json или переменных окружения"""
        # Поиск файла config.local.json в корне проекта
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        local_cfg_path = os.path.join(base_dir, "config.local.json")

        if os.path.exists(local_cfg_path):
            try:
                with open(local_cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "vps_ip" in data:
                        self.vps_ip = data["vps_ip"]
                    if "vps_port" in data:
                        self.vps_port = int(data["vps_port"])
                    if "ssh_port" in data:
                        self.ssh_port = int(data["ssh_port"])
                    if "panel_local_port" in data:
                        self.panel_local_port = int(data["panel_local_port"])
                    if "panel_path" in data:
                        self.panel_path = data["panel_path"]
                    if "active_donor" in data:
                        self.active_donor = data["active_donor"]
            except Exception:
                pass

        # Переопределение через переменные окружения (для CI/CD и продвинутых пользователей)
        self.vps_ip = os.getenv("RADAR_VPS_IP", self.vps_ip)
        self.panel_path = os.getenv("RADAR_PANEL_PATH", self.panel_path)
        self.active_donor = os.getenv("RADAR_DONOR", self.active_donor)
