"""
Модуль отображения терминального интерфейса (TUI) с использованием Rich.
Отрисовывает таблицы сканирования доноров, отчёты Sentinel и ASCII QR-коды.
"""

from typing import List, Optional
import io
import sys
import qrcode
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

from radar.scanner import DonorScanResult
from radar.sentinel import SentinelReport

# Отключаем устаревший рендерер Windows Console, используем современный ANSI вывод
console = Console(legacy_windows=False, force_terminal=True)

BANNER_ART = """
[bold cyan]=======================================================[/]
[bold cyan]      REALITY RADAR & VPS SENTINEL  v1.2.0[/]
[bold yellow]   Аудит VLESS-REALITY · Валидация TLS 1.3 · Защита от ТСПУ[/]
[bold cyan]=======================================================[/]
"""

def print_banner():
    """Отображает главный логотип инструмента"""
    console.print(BANNER_ART)

def render_scan_table(results: List[DonorScanResult]):
    """Отрисовывает красивую цветную таблицу результатов сканирования доноров"""
    table = Table(
        title="[bold yellow]РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ДОНОРОВ REALITY[/]",
        box=box.ROUNDED,
        header_style="bold magenta",
        title_justify="center"
    )

    table.add_column("#", justify="center", style="dim", width=3)
    table.add_column("Домен / Донор", style="bold cyan", width=24)
    table.add_column("TLS", justify="center", width=8)
    table.add_column("ALPN", justify="center", width=6)
    table.add_column("CDN", justify="center", width=8)
    table.add_column("RTT", justify="right", width=9)
    table.add_column("Балл", justify="center", width=5)
    table.add_column("Статус", justify="center", width=12)

    for idx, r in enumerate(results, 1):
        # Оформление версии TLS
        tls_str = f"[bold green]{r.tls_version}[/]" if r.supports_tls13 else f"[red]{r.tls_version}[/]"

        # Оформление ALPN
        if r.supports_h2:
            alpn_str = "[green]h2[/]"
        elif r.alpn_selected:
            alpn_str = f"[yellow]{r.alpn_selected}[/]"
        else:
            alpn_str = "[red]None[/]"

        # Оформление CDN
        if r.is_cdn:
            cdn_str = f"[bold red]{r.cdn_provider}[/]"
        else:
            cdn_str = "[bold green]Чистый[/]"

        # Время отклика
        rtt_str = f"{r.total_rtt_ms:.1f} мс" if r.total_rtt_ms > 0 else "[red]Таймаут[/]"

        # Скоринг и грейд
        if r.grade == "PERFECT":
            score_str = f"[bold green]{r.score}[/]"
            verdict_short = "[bold green]★ Идеально[/]"
        elif r.grade == "GOOD":
            score_str = f"[bold yellow]{r.score}[/]"
            verdict_short = "[green]Рекомендован[/]"
        elif r.grade == "RISKY":
            score_str = f"[yellow]{r.score}[/]"
            verdict_short = "[yellow]Риск (TLS 1.2)[/]"
        else:
            score_str = f"[bold red]{r.score}[/]"
            verdict_short = f"[red]CDN ({r.cdn_provider})[/]" if r.is_cdn else "[red]Ошибка[/]"

        table.add_row(
            str(idx),
            r.domain,
            tls_str,
            alpn_str,
            cdn_str,
            rtt_str,
            score_str,
            verdict_short
        )

    console.print(table)

def render_detailed_donor_card(r: DonorScanResult):
    """Отрисовывает детальную карточку конкретного домена"""
    lines = []
    lines.append(f"[bold]Домен:[/] [cyan]{r.domain}[/] (IP: {r.ip or 'Не определён'})")
    lines.append(f"[bold]Протокол TLS:[/] {'[green]TLS 1.3 (Отлично)' if r.supports_tls13 else '[red]' + r.tls_version}")
    lines.append(f"[bold]ALPN Протокол:[/] {'[green]HTTP/2 (h2)' if r.supports_h2 else r.alpn_selected or 'Нет'}")
    lines.append(f"[bold]Шифр (Cipher):[/] [yellow]{r.cipher_name}[/] ({r.cipher_bits} бит)")
    lines.append(f"[bold]SSL Сертификат:[/] [white]{r.cert_issuer}[/] (Осталось: {r.cert_days_left} дней)")
    lines.append(f"[bold]CDN Присутствие:[/] {'[bold red]ОБНАРУЖЕН: ' + r.cdn_provider if r.is_cdn else '[bold green]ОТСУТСТВУЕТ (Чистый origin-сервер)'}")
    lines.append(f"[bold]Сетевая задержка:[/] TCP {r.tcp_ping_ms}мс + TLS {r.tls_handshake_ms}мс = [bold]{r.total_rtt_ms}мс[/]")
    lines.append(f"[bold]Итоговая оценка:[/] [bold green]{r.score}/100[/] ([bold]{r.grade}[/])")
    lines.append(f"[bold]Заключение:[/] [white]{r.verdict}[/]")

    border_color = "green" if r.grade in ("PERFECT", "GOOD") else "red"
    console.print(Panel("\n".join(lines), title=f"[bold]Аудит донора: {r.domain}[/]", border_style=border_color))

def render_sentinel_report(rep: SentinelReport):
    """Отрисовывает комплексный отчёт состояния безопасности VPS"""
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, min_width=60)
    table.add_column("Параметр", style="bold cyan")
    table.add_column("Значение", style="white")

    # Статусы портов
    vpn_text = "[bold green]ОТКРЫТ (VLESS-REALITY слушает порт 443)[/]" if rep.port_vpn_open else "[bold red]ЗАКРЫТ / СБОЙ[/]"
    ssh_text = "[bold green]ОТКРЫТ (Защищён fail2ban на порту 22)[/]" if rep.port_ssh_open else "[bold red]НЕДОСТУПЕН[/]"
    
    tun_text = (
        f"[bold green]АКТИВЕН[/] (Панель отвечает: HTTP {rep.panel_http_status})"
        if rep.port_panel_tunnel_open
        else f"[dim yellow]НЕ ПОДНЯТ[/] (Локальный порт {rep.panel_port} свободен)"
    )

    handshake_text = (
        f"[bold green]УСПЕШНО[/] ({rep.reality_tls_version}, {rep.reality_cipher})"
        if rep.reality_handshake_ok
        else "[bold red]ОШИБКА РУКОПОЖАТИЯ[/]"
    )

    table.add_row("IP сервера (Амстердам):", rep.vps_ip)
    table.add_row("Текущий активный донор:", f"[yellow]{rep.active_donor}[/]")
    table.add_row("Входящий порт 443 (VPN):", vpn_text)
    table.add_row("Входящий порт 22 (SSH):", ssh_text)
    table.add_row("Эмуляция REALITY Handshake:", handshake_text)
    table.add_row(f"Локальный туннель 3x-ui ({rep.panel_port}):", tun_text)
    
    if rep.ping_avg > 0:
        table.add_row("Сетевой отклик (RTT):", f"Min {rep.ping_min}мс / Avg {rep.ping_avg}мс / Max {rep.ping_max}мс")
        jitter_color = "green" if rep.jitter_ms < 10 else "yellow"
        table.add_row("Джиттер (стабильность):", f"[{jitter_color}]±{rep.jitter_ms} мс[/]")

    # Общий статус здоровья
    if "OPTIMAL" in rep.health_status:
        status_panel_color = "green"
    elif "HIGH JITTER" in rep.health_status or "DEGRADED" in rep.health_status:
        status_panel_color = "yellow"
    else:
        status_panel_color = "red"

    panel = Panel(
        table,
        title=f"[bold]SENTINEL WATCHDOG: [{status_panel_color}]{rep.health_status}[/][/]",
        border_style=status_panel_color
    )
    console.print(panel)

    if rep.warnings:
        warn_text = "\n".join(f"[bold yellow]• {w}[/]" for w in rep.warnings)
        console.print(Panel(warn_text, title="[bold yellow]Предупреждения безопасности[/]", border_style="yellow"))

def render_ascii_qr(data: str, title: str = "QR-код для импорта"):
    """Генерирует и отрисовывает ASCII QR-код прямо в терминале Windows"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=1,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Захватываем текстовый вывод QR-кода
    f = io.StringIO()
    qr.print_ascii(out=f, invert=True)
    ascii_art = f.getvalue()

    console.print(Panel(ascii_art, title=f"[bold cyan]{title}[/]", subtitle="[dim]Отсканируйте камерой в Happ или v2rayNG[/]", border_style="cyan"))
