"""
Модуль конфигурации Reality Radar & Sentinel.
Содержит настройки по умолчанию, безопасную загрузку локального конфига
и списки региональных доноров: Нидерланды (NL), Финляндия (FI), Литва (LT), Европа (EU).
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

# Региональные пулы доноров для REALITY (разбиты по странам и зонам)
REGIONAL_CANDIDATES: Dict[str, List[str]] = {
    # 🇳🇱 Нидерланды: Дата-центры, точки обмена трафиком, университеты
    "nl": [
        "speedtest.serverius.net",
        "ams-ix.net",
        "leaseweb.com",
        "nl-ix.net",
        "bit.nl",
        "transip.nl",
        "i3d.net",
        "hostnet.nl",
        "ftp.nluug.nl",
        "mirror.ams1.nl.leaseweb.net",
        "nl.alpinelinux.org",
        "archlinux.mirror.wearetriple.com",
        "mirror.cj2.nl",
        "tudelft.nl",
        "uva.nl",
        "vu.nl",
        "uu.nl",
        "rug.nl",
        "tue.nl"
    ],

    # 🇫🇮 Финляндия: Научные центры, университеты, финский IXP и медиа
    "fi": [
        "csc.fi",              # Государственный научный IT-центр Финляндии (CSC)
        "helsinki.fi",         # Хельсинкский университет
        "aalto.fi",            # Университет Аалто
        "funet.fi",            # Финская академическая сеть FUNET
        "ficix.fi",            # Точка обмена трафиком FICIX (Хельсинки)
        "yle.fi",              # Национальная телерадиокомпания Финляндии
        "oulu.fi",             # Университет Оулу
        "tuni.fi",             # Университет Тампере
        "lut.fi",              # Технологический университет LUT
        "utu.fi",              # Университет Турку
        "jyu.fi",              # Университет Ювяскюля
        "kela.fi",             # Служба социального страхования Финляндии
        "stat.fi"              # Статистическое управление Финляндии
    ],

    # 🇱🇹 Литва: Академическая сеть Litnet, университеты, точки обмена трафиком
    "lt": [
        "litnet.lt",           # Академическая и исследовательская сеть Литвы
        "vu.lt",               # Вильнюсский университет
        "ktu.lt",              # Каунасский технологический университет
        "vgtu.lt",             # Вильнюсский технический университет Гедиминаса
        "lrt.lt",              # Литовское национальное радио и телевидение
        "vdu.lt",              # Университет Витаутаса Великого
        "ku.lt",               # Клайпедский университет
        "litix.lt",            # Литовская точка обмена трафиком (LITIX)
        "mruni.eu"             # Университет Миколаса Ромериса
    ],

    # 🇪🇺 Общеевропейские нейтральные зеркала дистрибутивов и открытого ПО
    "eu": [
        "debian.org",
        "kernel.org",
        "videolan.org",
        "mozilla.org",
        "libreoffice.org",
        "kde.org",
        "archlinux.org",
        "alpinelinux.org"
    ]
}

def get_candidates_by_region(region: str = "nl") -> List[str]:
    """Возвращает список доменов для указанного региона ('nl', 'fi', 'lt', 'eu', 'all')"""
    region = region.lower().strip()
    if region == "all":
        all_domains = []
        for dom_list in REGIONAL_CANDIDATES.values():
            all_domains.extend(dom_list)
        # Удаляем дубликаты с сохранением порядка
        return list(dict.fromkeys(all_domains))
    
    if region in REGIONAL_CANDIDATES:
        return list(REGIONAL_CANDIDATES[region])
    
    # По умолчанию возвращаем пул Нидерландов
    return list(REGIONAL_CANDIDATES["nl"])

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
    threads: int = 12
    default_region: str = "all"
    candidates: List[str] = field(default_factory=lambda: get_candidates_by_region("all"))

    def __post_init__(self):
        """Загрузка приватных настроек из локального файла config.local.json или переменных окружения"""
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
                    if "default_region" in data:
                        self.default_region = data["default_region"]
                        self.candidates = get_candidates_by_region(self.default_region)
            except Exception:
                pass

        # Переопределение через переменные окружения
        self.vps_ip = os.getenv("RADAR_VPS_IP", self.vps_ip)
        self.panel_path = os.getenv("RADAR_PANEL_PATH", self.panel_path)
        self.active_donor = os.getenv("RADAR_DONOR", self.active_donor)
