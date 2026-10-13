"""
Главный диспетчер командной строки (CLI) Reality Radar & Sentinel v1.1.0.
Обрабатывает аргументы, запускает региональное сканирование, аудит VPS и интерактивное меню.
"""

import sys
import os
import argparse
import time
from typing import List, Optional
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

from radar.config import RadarConfig, REGIONAL_CANDIDATES, get_candidates_by_region
from radar.scanner import RealityScanner
from radar.sentinel import VpsSentinel
from radar.tunnel import TunnelManager
from radar.ui import (
    console,
    print_banner,
    render_scan_table,
    render_detailed_donor_card,
    render_sentinel_report,
    render_ascii_qr
)

def load_domains_from_file(file_path: str) -> List[str]:
    """Загружает список доменов из текстового файла (по одному на строку)"""
    if not os.path.exists(file_path):
        console.print(f"[bold red]Ошибка:[/] Файл '{file_path}' не найден.")
        return []
    
    domains = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            # Пропускаем комментарии и пустые строки
            if clean and not clean.startswith("#"):
                # Убираем протокол https:// если пользователь вставил полный URL
                clean = clean.replace("https://", "").replace("http://", "").split("/")[0]
                domains.append(clean)
    
    # Удаляем дубликаты
    return list(dict.fromkeys(domains))

def handle_scan(config: RadarConfig, region: str = "all", custom_domains: list = None, from_file: str = None):
    """Выполняет сканирование пула доноров с живым индикатором прогресса"""
    if custom_domains:
        domains = custom_domains
        region_title = "пользовательского списка"
    elif from_file:
        domains = load_domains_from_file(from_file)
        if not domains:
            return
        region_title = f"файла {from_file}"
    else:
        domains = get_candidates_by_region(region)
        region_names = {
            "all": "всей Европы (Нидерланды, Финляндия, Литва, зеркала Linux)",
            "nl": "Нидерландов 🇳🇱",
            "fi": "Финляндии 🇫🇮",
            "lt": "Литвы 🇱🇹",
            "eu": "общеевропейских зеркал ПО 🇪🇺"
        }
        region_title = region_names.get(region.lower(), region.upper())

    scanner = RealityScanner(timeout=config.timeout, max_workers=config.threads)

    console.print(f"[bold cyan]Запуск сканирования {len(domains)} узлов ({region_title})...[/]")
    console.print("[dim]Критерии: TLS 1.3 · HTTP/2 (ALPN) · Отсутствие CDN · Минимальный RTT[/]\n")

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Тестирование узлов...", total=len(domains))
        
        # Сканируем параллельно, обновляя прогресс
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_domain = {executor.submit(scanner.check_single_domain, dom): dom for dom in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    dom = future_to_domain[future]
                    from radar.scanner import DonorScanResult
                    results.append(DonorScanResult(domain=dom, error_message=str(e)))
                progress.advance(task)

    results.sort(key=lambda x: x.score, reverse=True)
    console.print("\n")
    render_scan_table(results)

    # Выделяем абсолютного лидера
    best = [r for r in results if r.grade == "PERFECT"]
    if best:
        console.print(f"\n[bold green]★ ТОП-1 РЕКОМЕНДАЦИЯ ДЛЯ REALITY:[/] [bold cyan]{best[0].domain}[/] "
                      f"(Скоринг: {best[0].score}/100, Пинг: {best[0].total_rtt_ms}мс)")
        console.print(f"[dim]Используйте в поле 'Dest / ServerNames' панели 3x-ui: {best[0].domain}:443[/]\n")

def handle_check(domain: str, config: RadarConfig):
    """Выполняет глубокую проверку одного целевого домена"""
    console.print(f"[bold cyan]Глубокий аудит домена {domain}...[/]\n")
    scanner = RealityScanner(timeout=config.timeout)
    res = scanner.check_single_domain(domain)
    render_detailed_donor_card(res)

def handle_vps_status(config: RadarConfig):
    """Выполняет полный аудит нашего сервера в Амстердаме"""
    console.print(f"[bold cyan]Запуск Sentinel Watchdog для сервера {config.vps_ip}...[/]\n")
    sentinel = VpsSentinel(
        vps_ip=config.vps_ip,
        vpn_port=config.vps_port,
        ssh_port=config.ssh_port,
        panel_port=config.panel_local_port,
        panel_path=config.panel_path,
        active_donor=config.active_donor
    )
    report = sentinel.run_full_diagnostic()
    render_sentinel_report(report)

def handle_tunnel(action: str, config: RadarConfig):
    """Управляет состоянием SSH-туннеля к 3x-ui"""
    tm = TunnelManager(
        vps_ip=config.vps_ip,
        panel_port=config.panel_local_port,
        panel_path=config.panel_path,
        ssh_port=config.ssh_port
    )

    if action == "status":
        active = tm.is_tunnel_active()
        status_text = "[bold green]АКТИВЕН (порт 5541 слушает)[/]" if active else "[yellow]ОТКЛЮЧЁН[/]"
        console.print(f"Статус SSH-туннеля: {status_text}")
        if active:
            console.print(f"Адрес панели: [cyan]{tm.get_panel_url()}[/]")
    elif action == "start":
        console.print("[cyan]Подъём фонового SSH-туннеля к 3x-ui...[/]")
        ok, msg = tm.start_tunnel(open_browser=True)
        style = "bold green" if ok else "bold red"
        console.print(f"[{style}]{msg}[/]")
    elif action == "stop":
        console.print("[cyan]Остановка туннеля...[/]")
        ok, msg = tm.stop_tunnel()
        console.print(f"[yellow]{msg}[/]")
    elif action == "open":
        tm.open_browser()
        console.print("[green]Страница панели открыта в браузере.[/]")

def handle_qr(data: str):
    """Отрисовывает QR-код в консоли"""
    render_ascii_qr(data, title="VLESS Ключ / Ссылка")

def interactive_menu(config: RadarConfig):
    """Интерактивное консольное меню для удобной работы в один клик"""
    while True:
        print_banner()
        console.print("[bold white]Выберите действие:[/]")
        console.print("  [bold cyan]1.[/] Сканировать всех доноров Европы (NL + FI + LT + EU)")
        console.print("  [bold cyan]2.[/] Сканировать по странам: 🇳🇱 Нидерланды / 🇫🇮 Финляндия / 🇱🇹 Литва")
        console.print("  [bold cyan]3.[/] Сканировать список доменов из текстового файла")
        console.print("  [bold cyan]4.[/] Проверить конкретный сайт на пригодность (Deep Check)")
        console.print("  [bold cyan]5.[/] Диагностика здоровья VPS и порта 443 (Sentinel Watchdog)")
        console.print("  [bold cyan]6.[/] Поднять туннель к 3x-ui и открыть админку в браузере")
        console.print("  [bold cyan]7.[/] Сгенерировать терминальный QR-код для ссылки VLESS")
        console.print("  [bold red]0.[/] Выход\n")

        choice = Prompt.ask("[bold yellow]Ваш выбор[/]", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="1")

        if choice == "1":
            handle_scan(config, region="all")
        elif choice == "2":
            console.print("\n[bold white]Выберите регион:[/]")
            console.print("  [bold cyan]nl[/] — 🇳🇱 Нидерланды (Амстердам, Serverius, Leaseweb, AMS-IX)")
            console.print("  [bold cyan]fi[/] — 🇫🇮 Финляндия (Хельсинки, CSC, Aalto, FICIX, Yle)")
            console.print("  [bold cyan]lt[/] — 🇱🇹 Литва (Вильнюс, Litnet, VU, KTU, LRT)")
            console.print("  [bold cyan]eu[/] — 🇪🇺 Общеевропейские нейтральные зеркала ПО (Debian, Arch, Kernel)")
            reg = Prompt.ask("[bold yellow]Регион[/]", choices=["nl", "fi", "lt", "eu"], default="fi")
            handle_scan(config, region=reg)
        elif choice == "3":
            f_path = Prompt.ask("[bold cyan]Укажите путь к текстовому файлу (например, domains.txt)[/]")
            if f_path.strip():
                handle_scan(config, from_file=f_path.strip())
        elif choice == "4":
            target = Prompt.ask("[bold cyan]Введите имя домена (например, csc.fi или vu.lt)[/]")
            if target.strip():
                handle_check(target.strip(), config)
        elif choice == "5":
            handle_vps_status(config)
        elif choice == "6":
            handle_tunnel("start", config)
        elif choice == "7":
            link = Prompt.ask("[bold cyan]Вставьте ссылку vless://...[/]")
            if link.strip():
                handle_qr(link.strip())
        elif choice == "0":
            console.print("[green]До встречи! Ваша крепость под защитой.[/]")
            break

        Prompt.ask("\n[dim]Нажмите Enter, чтобы вернуться в меню...[/]")
        console.clear()

def main():
    """Точка входа CLI"""
    config = RadarConfig()

    parser = argparse.ArgumentParser(
        description="Reality Radar & Sentinel CLI v1.1.0 — инструмент аудита VLESS-REALITY и VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Команда для выполнения")

    # Команда scan
    p_scan = subparsers.add_parser("scan", help="Сканировать список доноров")
    p_scan.add_argument("--region", "-r", choices=["nl", "fi", "lt", "eu", "all"], default="all",
                        help="Региональный фильтр (по умолчанию: all)")
    p_scan.add_argument("--file", "-f", help="Путь к текстовому файлу со списком доменов")
    p_scan.add_argument("--domain", "-d", nargs="+", help="Пользовательский список доменов через пробел")

    # Команда check
    p_check = subparsers.add_parser("check", help="Глубокая проверка одного домена")
    p_check.add_argument("target", help="Домен для проверки (например: csc.fi или speedtest.serverius.net)")

    # Команда vps
    subparsers.add_parser("vps", help="Аудит здоровья и доступности сервера VPS")

    # Команда tunnel
    p_tunnel = subparsers.add_parser("tunnel", help="Управление SSH-туннелем к панели")
    p_tunnel.add_argument("action", choices=["start", "stop", "status", "open"], help="Действие с туннелем")

    # Команда qr
    p_qr = subparsers.add_parser("qr", help="Отрисовать ASCII QR-код для VLESS ссылки")
    p_qr.add_argument("data", help="VLESS ссылка для генерации QR-кода")

    args = parser.parse_args()

    if not args.command:
        interactive_menu(config)
    else:
        print_banner()
        if args.command == "scan":
            handle_scan(config, region=args.region, custom_domains=args.domain, from_file=args.file)
        elif args.command == "check":
            handle_check(args.target, config)
        elif args.command == "vps":
            handle_vps_status(config)
        elif args.command == "tunnel":
            handle_tunnel(args.action, config)
        elif args.command == "qr":
            handle_qr(args.data)

if __name__ == "__main__":
    main()
