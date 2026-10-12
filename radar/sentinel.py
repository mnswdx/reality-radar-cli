"""
Модуль мониторинга здоровья и безопасности сервера VPS (Sentinel Watchdog).
Проверяет доступность портов, эмулирует TLS handshake к ядру Xray и замеряет джиттер.
"""

import socket
import ssl
import time
import math
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple

from radar.config import (
    DEFAULT_VPS_IP,
    DEFAULT_VPS_PORT,
    DEFAULT_SSH_PORT,
    DEFAULT_PANEL_LOCAL_PORT,
    DEFAULT_PANEL_PATH,
    DEFAULT_ACTIVE_DONOR
)

@dataclass
class SentinelReport:
    """Итоговый отчёт о состоянии сервера и туннелей"""
    vps_ip: str
    active_donor: str
    port_vpn_open: bool = False
    port_ssh_open: bool = False
    port_panel_tunnel_open: bool = False
    reality_handshake_ok: bool = False
    reality_tls_version: str = "Unknown"
    reality_cipher: str = ""
    panel_http_status: int = 0
    ping_samples: List[float] = field(default_factory=list)
    ping_min: float = 0.0
    ping_avg: float = 0.0
    ping_max: float = 0.0
    jitter_ms: float = 0.0
    health_status: str = "UNKNOWN"
    warnings: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)

class VpsSentinel:
    """Мониторинг доступности узла и эмуляция рукопожатий REALITY"""

    def __init__(
        self,
        vps_ip: str = DEFAULT_VPS_IP,
        vpn_port: int = DEFAULT_VPS_PORT,
        ssh_port: int = DEFAULT_SSH_PORT,
        panel_port: int = DEFAULT_PANEL_LOCAL_PORT,
        panel_path: str = DEFAULT_PANEL_PATH,
        active_donor: str = DEFAULT_ACTIVE_DONOR,
        timeout: float = 3.5
    ):
        self.vps_ip = vps_ip
        self.vpn_port = vpn_port
        self.ssh_port = ssh_port
        self.panel_port = panel_port
        self.panel_path = panel_path
        self.active_donor = active_donor
        self.timeout = timeout

    def check_tcp_port(self, host: str, port: int, timeout: float = 2.5) -> Tuple[bool, float]:
        """Проверяет доступность TCP порта и замеряет RTT"""
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                latency = (time.perf_counter() - t0) * 1000.0
                return True, round(latency, 2)
        except Exception:
            return False, 0.0

    def measure_jitter(self, count: int = 5) -> Tuple[List[float], float, float, float, float]:
        """Делает серию сетевых замеров для расчёта среднего RTT и джиттера (вариации задержки)"""
        samples = []
        for _ in range(count):
            ok, lat = self.check_tcp_port(self.vps_ip, self.vpn_port, timeout=2.0)
            if ok:
                samples.append(lat)
            time.sleep(0.08)

        if not samples:
            return [], 0.0, 0.0, 0.0, 0.0

        p_min = min(samples)
        p_max = max(samples)
        p_avg = sum(samples) / len(samples)

        # Вычисление стандартного отклонения (джиттер)
        if len(samples) > 1:
            variance = sum((x - p_avg) ** 2 for x in samples) / (len(samples) - 1)
            jitter = math.sqrt(variance)
        else:
            jitter = 0.0

        return samples, round(p_min, 2), round(p_avg, 2), round(p_max, 2), round(jitter, 2)

    def probe_reality_handshake(self) -> Tuple[bool, str, str, str]:
        """
        Эмулирует реальное TLS-рукопожатие клиента к порту 443 нашего VPS.
        Передаёт SNI донора (speedtest.serverius.net) и проверяет,
        что ядро Xray корректно подменяет сертификат и откликается по TLS 1.3.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        try:
            with socket.create_connection((self.vps_ip, self.vpn_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.active_donor) as sslobj:
                    ver = sslobj.version() or "Unknown"
                    cipher = sslobj.cipher()[0] if sslobj.cipher() else "Unknown"
                    return True, ver, cipher, "Успешное TLS рукопожатие с Xray"
        except Exception as e:
            return False, "None", "None", f"Сбой TLS: {str(e)}"

    def check_local_panel_tunnel(self) -> Tuple[bool, int]:
        """Проверяет, поднят ли локальный SSH-туннель к веб-панели 3x-ui"""
        url = f"http://127.0.0.1:{self.panel_port}{self.panel_path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 Sentinel"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return True, resp.getcode()
        except urllib.error.HTTPError as e:
            # Код 404/401/200 подтверждает, что веб-сервер панели отвечает
            return True, e.code
        except Exception:
            return False, 0

    def run_full_diagnostic(self) -> SentinelReport:
        """Запускает полную комплексную диагностику всех узлов защиты"""
        report = SentinelReport(vps_ip=self.vps_ip, active_donor=self.active_donor)

        # 1. Проверка порта 443 (VPN)
        vpn_ok, vpn_lat = self.check_tcp_port(self.vps_ip, self.vpn_port)
        report.port_vpn_open = vpn_ok
        if not vpn_ok:
            report.warnings.append("Порт 443 недоступен! Возможно, служба Xray остановлена или заблокирована.")

        # 2. Проверка порта 22 (SSH)
        ssh_ok, ssh_lat = self.check_tcp_port(self.vps_ip, self.ssh_port)
        report.port_ssh_open = ssh_ok
        if not ssh_ok:
            report.warnings.append("Порт 22 недоступен! Проверьте статус SSH или блокировку в fail2ban.")

        # 3. Эмуляция REALITY Handshake
        if vpn_ok:
            r_ok, r_ver, r_cip, r_msg = self.probe_reality_handshake()
            report.reality_handshake_ok = r_ok
            report.reality_tls_version = r_ver
            report.reality_cipher = r_cip
            if not r_ok:
                report.warnings.append(f"Рукопожатие REALITY не удалось: {r_msg}")
            elif r_ver != "TLSv1.3":
                report.warnings.append(f"Внимание: получена версия {r_ver} вместо строгого TLS 1.3.")

        # 4. Проверка джиттера и пинга
        samples, p_min, p_avg, p_max, jitter = self.measure_jitter()
        report.ping_samples = samples
        report.ping_min = p_min
        report.ping_avg = p_avg
        report.ping_max = p_max
        report.jitter_ms = jitter

        # 5. Проверка локального SSH-туннеля к 3x-ui
        tun_ok, tun_code = self.check_local_panel_tunnel()
        report.port_panel_tunnel_open = tun_ok
        report.panel_http_status = tun_code

        # 6. Определение итогового статуса
        if report.port_vpn_open and report.reality_handshake_ok and report.port_ssh_open:
            if report.jitter_ms < 15.0:
                report.health_status = "HEALTHY (OPTIMAL)"
            else:
                report.health_status = "HEALTHY (HIGH JITTER)"
        elif report.port_vpn_open:
            report.health_status = "DEGRADED"
        else:
            report.health_status = "CRITICAL (DOWN)"

        return report
