"""
Модуль сканирования и глубокого анализа доноров REALITY (SNI Radar).
Проверяет TLS 1.3, ALPN (h2/http1.1), шифры, задержку (RTT) и отсеивает CDN.
"""

import socket
import ssl
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import urllib.parse

from radar.config import KNOWN_CDN_HEADERS

@dataclass
class DonorScanResult:
    """Результат детальной проверки домена на пригодность под REALITY"""
    domain: str
    ip: str = ""
    is_accessible: bool = False
    tls_version: str = "Unknown"
    supports_tls13: bool = False
    alpn_selected: Optional[str] = None
    supports_h2: bool = False
    cipher_name: str = ""
    cipher_bits: int = 0
    cert_issuer: str = ""
    cert_days_left: int = 0
    is_cdn: bool = False
    cdn_provider: str = ""
    tcp_ping_ms: float = 0.0
    tls_handshake_ms: float = 0.0
    total_rtt_ms: float = 0.0
    score: int = 0
    grade: str = "FAIL"  # PERFECT, GOOD, RISKY, UNUSABLE
    verdict: str = ""
    error_message: str = ""

class RealityScanner:
    """Многопоточный сканер для валидации доменов-доноров REALITY"""

    def __init__(self, timeout: float = 3.5, max_workers: int = 8):
        self.timeout = timeout
        self.max_workers = max_workers

    def check_single_domain(self, domain: str) -> DonorScanResult:
        """
        Проводит глубокую проверку одного домена:
        1. Разрешение DNS
        2. Замер задержки TCP-рукопожатия
        3. Валидация TLS 1.3 и отпечатка ALPN
        4. Анализ сертификата
        5. Проверка заголовков ответа на сигнатуры CDN
        6. Расчёт итоговой оценки
        """
        result = DonorScanResult(domain=domain)
        
        # 1. Разрешение DNS
        try:
            addr_info = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                result.error_message = "DNS: IP не найден"
                result.verdict = "Не удалось разрешить IP-адрес"
                return result
            ip = addr_info[0][4][0]
            result.ip = ip
        except Exception as e:
            result.error_message = f"DNS ошибка: {str(e)}"
            result.verdict = "Ошибка разрешения DNS"
            return result

        # 2. Проверка TCP соединения и замер RTT
        t0 = time.perf_counter()
        sock = None
        try:
            sock = socket.create_connection((ip, 443), timeout=self.timeout)
            tcp_time = (time.perf_counter() - t0) * 1000.0
            result.tcp_ping_ms = round(tcp_time, 2)
            result.is_accessible = True
        except Exception as e:
            result.error_message = f"TCP порт 443 недоступен: {str(e)}"
            result.verdict = "Порт 443 не отвечает"
            return result

        # 3. Настройка защищённого контекста TLS с запросом ALPN (h2, http/1.1)
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        # Разрешаем протоколы TLS 1.2 и 1.3
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Запрашиваем протоколы прикладного уровня ALPN
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (AttributeError, NotImplementedError):
            pass

        # 4. Выполнение TLS рукопожатия с измерением времени
        tls_start = time.perf_counter()
        sslobj = None
        try:
            sslobj = ctx.wrap_socket(sock, server_hostname=domain)
            tls_time = (time.perf_counter() - tls_start) * 1000.0
            result.tls_handshake_ms = round(tls_time, 2)
            result.total_rtt_ms = round(result.tcp_ping_ms + result.tls_handshake_ms, 2)

            # Извлечение параметров соединения
            version = sslobj.version()
            result.tls_version = version or "Unknown"
            result.supports_tls13 = (version == "TLSv1.3")

            selected_alpn = sslobj.selected_alpn_protocol()
            result.alpn_selected = selected_alpn
            result.supports_h2 = (selected_alpn == "h2")

            cipher_info = sslobj.cipher()
            if cipher_info:
                result.cipher_name = cipher_info[0]
                result.cipher_bits = cipher_info[2]

            # Извлечение данных сертификата
            cert = sslobj.getpeercert()
            if cert:
                # Извлекаем издателя сертификата (Issuer)
                issuer_components = cert.get("issuer", ())
                issuer_names = []
                for field_group in issuer_components:
                    for k, val in field_group:
                        if k in ("organizationName", "commonName"):
                            issuer_names.append(val)
                result.cert_issuer = " / ".join(issuer_names) if issuer_names else "Unknown"

                # Срок действия сертификата
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        # Формат времени сертификата: 'May 15 12:00:00 2026 GMT'
                        expire_time = ssl.cert_time_to_seconds(not_after)
                        days_left = int((expire_time - time.time()) / 86400)
                        result.cert_days_left = max(0, days_left)
                    except Exception:
                        pass

        except ssl.SSLCertVerificationError as e:
            result.error_message = f"Ошибка сертификата: {str(e)}"
            result.verdict = "Недействительный SSL-сертификат"
            if sock:
                try: sock.close()
                except: pass
            return result
        except Exception as e:
            result.error_message = f"Ошибка TLS handshake: {str(e)}"
            result.verdict = "Сбой TLS рукопожатия"
            if sock:
                try: sock.close()
                except: pass
            return result

        # 5. Проверка заголовков ответа на обнаружение CDN
        try:
            # Отправляем легковесный HTTP HEAD запрос
            request_bytes = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("utf-8")
            sslobj.sendall(request_bytes)
            
            # Читаем заголовки ответа
            response_data = b""
            sslobj.settimeout(2.0)
            while True:
                chunk = sslobj.recv(2048)
                if not chunk:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data or len(response_data) > 8192:
                    break

            headers_text = response_data.decode("utf-8", errors="ignore").lower()
            
            # Проверяем сигнатуры известных CDN
            if "cf-ray" in headers_text or "cloudflare" in headers_text:
                result.is_cdn = True
                result.cdn_provider = "Cloudflare"
            elif "akamai" in headers_text or "x-akamai" in headers_text:
                result.is_cdn = True
                result.cdn_provider = "Akamai"
            elif "fastly" in headers_text:
                result.is_cdn = True
                result.cdn_provider = "Fastly"
            elif "incap-ses" in headers_text:
                result.is_cdn = True
                result.cdn_provider = "Incapsula"
            elif "server: amazon" in headers_text or "cloudfront" in headers_text:
                result.is_cdn = True
                result.cdn_provider = "CloudFront"

        except Exception:
            # Если веб-сервер не ответил на HEAD — это не критично для REALITY, продолжаем анализ
            pass
        finally:
            if sslobj:
                try: sslobj.close()
                except: pass
            elif sock:
                try: sock.close()
                except: pass

        # 6. Расчёт итогового скоринга (0 - 100)
        self._calculate_score(result)
        return result

    def _calculate_score(self, r: DonorScanResult):
        """Оценивает донор по ключевым критериям безопасности VLESS-REALITY"""
        score = 0
        reasons = []

        # Базовое требование: TLS 1.3
        if r.supports_tls13:
            score += 35
            reasons.append("TLS 1.3 поддерживается")
        else:
            reasons.append("TLS 1.2 (устаревает, легче детектируется)")

        # Поддержка HTTP/2 через ALPN
        if r.supports_h2:
            score += 25
            reasons.append("HTTP/2 (h2) подтвержден")
        elif r.alpn_selected:
            score += 10
            reasons.append(f"ALPN: {r.alpn_selected}")

        # Проверка отсутствия CDN
        if not r.is_cdn:
            score += 25
            reasons.append("Прямой сервер (не за CDN)")
        else:
            score -= 40
            reasons.append(f"ВНИМАНИЕ: Обнаружен CDN {r.cdn_provider} (вызывает сбои REALITY)")

        # Время отклика (RTT)
        if r.total_rtt_ms > 0:
            if r.total_rtt_ms < 60:
                score += 15
                reasons.append(f"Отличный пинг: {r.total_rtt_ms}мс")
            elif r.total_rtt_ms < 120:
                score += 10
                reasons.append(f"Нормальный пинг: {r.total_rtt_ms}мс")
            else:
                score += 5
                reasons.append(f"Высокий пинг: {r.total_rtt_ms}мс")

        # Итоговая нормализация баллов
        score = max(0, min(100, score))
        r.score = score

        # Присвоение категории пригодности
        if score >= 85 and r.supports_tls13 and not r.is_cdn:
            r.grade = "PERFECT"
            r.verdict = "Идеальный донор для REALITY (TLS 1.3 + h2, прямой узел)"
        elif score >= 65 and not r.is_cdn:
            r.grade = "GOOD"
            r.verdict = "Хороший кандидат (подходит для боевого использования)"
        elif r.is_cdn:
            r.grade = "UNUSABLE"
            r.verdict = f"Непригоден для REALITY (спрятан за CDN: {r.cdn_provider})"
        elif not r.supports_tls13:
            r.grade = "RISKY"
            r.verdict = "Рискованный (только TLS 1.2, повышенный риск детекта ТСПУ)"
        else:
            r.grade = "UNUSABLE"
            r.verdict = "Низкие показатели стабильности"

    def scan_domain_list(self, domains: List[str]) -> List[DonorScanResult]:
        """Параллельное сканирование списка доменов в несколько потоков"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.check_single_domain, dom): dom for dom in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    dom = future_to_domain[future]
                    bad_res = DonorScanResult(domain=dom, error_message=str(e), verdict="Ошибка потока")
                    results.append(bad_res)
        
        # Сортировка по скорингу (лучшие кандидаты сверху)
        results.sort(key=lambda x: x.score, reverse=True)
        return results
