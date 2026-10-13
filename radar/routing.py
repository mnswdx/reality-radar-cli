"""
Модуль интеграции умной маршрутизации SplitStream в Reality Radar CLI.
Генерирует нативные диплинки Happ, копирует в буфер обмена и запускает импорт.
"""

import sys
import os
import json
import base64
import time
import subprocess
from typing import Tuple

from radar.ui import console, render_ascii_qr
from rich.panel import Panel
from rich.text import Text


def generate_happ_turbo_link() -> Tuple[str, dict]:
    """
    Генерирует нативную ссылку happ://routing/add/ для профиля SplitStream Turbo RU
    со скоростными зеркалами ghproxy для обхода замедлений GitHub Releases в РФ.
    """
    payload = {
        "Name": "SplitStream Turbo RU",
        "GeositeUrl": "https://ghproxy.net/https://github.com/kepler103b/geo-for-ru-only/releases/download/latest/geosite.dat",
        "GeoipUrl": "https://ghproxy.net/https://github.com/kepler103b/geo-for-ru-only/releases/download/latest/geoip.dat",
        "DirectIp": [
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255",
            "geoip:ru",
            "geoip:private"
        ],
        "DirectSites": [
            "ru",
            "su",
            "xn--p1ai",
            "by",
            "kz",
            "geosite:vk",
            "geosite:kinopoisk",
            "geosite:aviasales",
            "geosite:drweb",
            "geosite:wildberries",
            "geosite:rutube",
            "geosite:ozon",
            "geosite:wink",
            "geosite:2gis",
            "geosite:kaspersky",
            "geosite:ok",
            "geosite:yandex",
            "geosite:okko",
            "geosite:avito",
            "geosite:mosmetro",
            "geosite:dzen",
            "geosite:mailru",
            "geosite:mailru-group",
            "geosite:category-travel-ru",
            "geosite:x5",
            "geosite:category-gov-ru",
            "geosite:category-entertainment-ru",
            "geosite:category-retail-ru",
            "geosite:category-medicine-ru",
            "geosite:category-media-ru",
            "geosite:category-ecommerce-ru",
            "geosite:category-ru",
            "geosite:category-bank-ru"
        ],
        "ProxySites": [
            "youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "youtu.be",
            "discord.com",
            "discordapp.com",
            "discord.gg",
            "discord.media",
            "discordapp.net",
            "instagram.com",
            "cdninstagram.com",
            "threads.net",
            "twitter.com",
            "x.com",
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "claude.ai",
            "anthropic.com",
            "rutracker.org",
            "flibusta.is",
            "nnmclub.to"
        ],
        "ProxyIp": [],
        "BlockSites": [],
        "BlockIp": [],
        "GlobalProxy": True,
        "RouteOrder": "block-direct-proxy",
        "DomainStrategy": "IPIfNonMatch",
        "FakeDns": True,
        "UseChunkFiles": True,
        "DomesticDNSIp": "1.0.0.1",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "https://dns.google/dns-query",
        "RemoteDNSIp": "1.1.1.1",
        "RemoteDNSType": "DoU",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "DnsHosts": {
            "cloudflare-dns.com": "1.1.1.1",
            "dns.google": "8.8.8.8"
        },
        "LastUpdated": int(time.time())
    }

    json_str = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    deeplink = f"happ://routing/add/{b64_str}"
    return deeplink, payload


def copy_to_clipboard(text: str) -> bool:
    """Копирует текст в буфер обмена Windows"""
    try:
        process = subprocess.Popen(["clip"], stdin=subprocess.PIPE, close_fds=True)
        process.communicate(input=text.encode("utf-8"))
        return True
    except Exception:
        return False


def handle_routing_menu():
    """Интерактивный экран генерации и применения профиля маршрутизации"""
    link, payload = generate_happ_turbo_link()

    console.print("\n[bold cyan]⚡ Генератор профиля маршрутизации SplitStream Turbo RU[/bold cyan]\n")

    # Копируем ссылку в буфер обмена
    copied = copy_to_clipboard(link)
    clipboard_status = "[bold green]✓ Ссылка скопирована в буфер обмена![/]" if copied else "[yellow]Скопируйте ссылку вручную[/]"

    info_text = Text()
    info_text.append(f"Профиль: {payload['Name']}\n", style="bold white")
    info_text.append("• Прямой доступ (Direct): Банки, Госуслуги, Ozon, WB, Яндекс, VK, зоны .ru/.рф\n", style="green")
    info_text.append("• Туннель VPN (Proxy): YouTube (4K), Discord, Instagram, ChatGPT, Claude\n", style="magenta")
    info_text.append("• Зеркала баз Geo: Высокоскоростной CDN (ghproxy.net, мгновенная загрузка)\n\n", style="cyan")
    info_text.append(f"Статус буфера обмена: {clipboard_status}\n", style="bold yellow")

    panel = Panel(info_text, title="[bold]ПАРАМЕТРЫ МАРШРУТИЗАЦИИ[/]", border_style="bright_blue")
    console.print(panel)

    console.print("[dim]Ссылка для Happ:[/dim]")
    console.print(f"[cyan]{link[:100]}...[/cyan]\n")

    console.print("Действия:")
    console.print("  [bold green]1.[/] Открыть ссылку прямо сейчас в приложении Happ на ПК")
    console.print("  [bold yellow]2.[/] Отрисовать QR-код (для сканирования камерой телефона)")
    console.print("  [bold white]0.[/] Назад в главное меню\n")

    from rich.prompt import Prompt
    action = Prompt.ask("Выберите действие", choices=["0", "1", "2"], default="1")

    if action == "1":
        try:
            if sys.platform == "win32":
                os.startfile(link)
                console.print("[bold green]✓ Команда отправлена в Happ! Проверьте окно приложения.[/]")
            else:
                subprocess.Popen(["xdg-open", link])
        except Exception as e:
            console.print(f"[bold red]Не удалось запустить приложение: {e}[/]")
    elif action == "2":
        try:
            render_ascii_qr(link, title="SplitStream Turbo RU — QR-код для Happ")
        except Exception as e:
            console.print(f"[yellow]QR-код слишком велик для окна терминала. Используйте скопированную ссылку из буфера обмена![/]")
