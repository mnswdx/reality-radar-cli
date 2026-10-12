"""
Главный диспетчер командной строки (CLI) Reality Radar & Sentinel.
Обрабатывает аргументы, запускает сканирование, аудит VPS и интерактивное меню.
"""

import sys
import argparse
import time
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

from radar.config import RadarConfig, CURATED_CANDIDATES
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

def handle_scan(config: RadarConfig, custom_domains: list = None):
    """Выполняет сканирование пула доноров с живым индикатором прогресса"""
    domains = custom_domains if custom_domains else config.candidates
    scanner = RealityScanner(timeout=config.timeout, max_workers=config.threads)

    console.print(f"[bold cyan]Запуск сканирования {len(domains)} европейских узлов-кандидатов...[/]")
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
        console.print("  [bold cyan]1.[/] Сканировать европейских доноров REALITY (SNI Radar)")
        console.print("  [bold cyan]2.[/] Проверить конкретный домен на пригодность (Deep Check)")
        console.print("  [bold cyan]3.[/] Диагностика здоровья VPS и порта 443 (Sentinel Watchdog)")
        console.print("  [bold cyan]4.[/] Поднять туннель к 3x-ui и открыть админку в браузере")
        console.print("  [bold cyan]5.[/] Остановить SSH-туннель")
        console.print("  [bold cyan]6.[/] Сгенерировать терминальный QR-код для ссылки VLESS")
        console.print("  [bold red]0.[/] Выход\n")

        choice = Prompt.ask("[bold yellow]Ваш выбор[/]", choices=["0", "1", "2", "3", "4", "5", "6"], default="3")

        if choice == "1":
            handle_scan(config)
        elif choice == "2":
            target = Prompt.ask("[bold cyan]Введите имя домена (например, speedtest.serverius.net)[/]")
            if target.strip():
                handle_check(target.strip(), config)
        elif choice == "3":
            handle_vps_status(config)
        elif choice == "4":
            handle_tunnel("start", config)
        elif choice == "5":
            handle_tunnel("stop", config)
        elif choice == "6":
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
        description="Reality Radar & Sentinel CLI — инструмент аудита VLESS-REALITY и VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Команда для выполнения")

    # Команда scan
    p_scan = subparsers.add_parser("scan", help="Сканировать список европейских доноров")
    p_scan.add_argument("--domain", "-d", nargs="+", help="Пользовательский список доменов")

    # Команда check
    p_check = subparsers.add_parser("check", help="Глубокая проверка одного домена")
    p_check.add_argument("target", help="Домен для проверки (например: speedtest.serverius.net)")

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
        # Если аргументы не переданы — открываем красивое интерактивное меню
        interactive_menu(config)
    else:
        print_banner()
        if args.command == "scan":
            handle_scan(config, custom_domains=args.domain)
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
