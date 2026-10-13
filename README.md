# 🛰️ Reality Radar & Sentinel CLI

[![Release: v1.1.0](https://img.shields.io/badge/Release-v1.1.0-brightgreen.svg)](https://github.com/mnswdx/reality-radar-cli/releases)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-yellow.svg)]()
[![Platform: Windows | Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-orange.svg)]()
[![Protocol: VLESS--REALITY](https://img.shields.io/badge/Protocol-VLESS--REALITY-purple.svg)]()

Профессиональный инструмент мониторинга, аудита безопасности и валидации доменов-доноров для **VLESS-REALITY (Xray / 3x-ui)**.

Разработан для аудита безопасности, проверки маскировки и мониторинга любого VPS-сервера на базе VLESS-REALITY.

---

## ⚡ Ключевые возможности

1. **SNI Radar (Многопоточный сканер доноров):**
   - Анализ пула европейских и нидерландских серверов (дата-центры, точки обмена трафиком, университеты).
   - Проверка обязательного протокола **TLS 1.3** и шифров нового поколения (X25519).
   - Валидация поддержки **HTTP/2 (h2)** через протокол ALPN.
   - **Детектор CDN:** автоматическое обнаружение Cloudflare, Akamai, Fastly и отбраковка неподходящих доменов (защита от IP-SNI Mismatch).
   - Замер реального времени отклика (**TCP Ping + TLS Handshake RTT**) и скоринг пригодности (0–100 баллов).

2. **Sentinel Watchdog (Аудит сервера VPS):**
   - Проверка доступности портов `443` (VLESS-REALITY) и `22` (SSH / Fail2ban).
   - **Эмуляция активного зондирования:** отправка пакета `ClientHello` к ядру Xray с целевым SNI для подтверждения корректной работы подмены сертификата.
   - Замер сетевого джиттера (вариации задержки по 5 замерам).
   - Проверка локального SSH-туннеля к веб-панели 3x-ui (`http://127.0.0.1:5541`).

3. **Smart Tunnel Manager:**
   - Подъём, проверка статуса и безопасная остановка SSH-туннеля к админке в один клик.
   - Автоматическое открытие страницы панели 3x-ui в браузере.

4. **Генератор Terminal ASCII QR:**
   - Отрисовка QR-кодов для VLESS-ссылок прямо в терминале Windows (для мгновенного сканирования камерой смартфона или планшета).

---

## 📥 Установка и настройка

1. **Клонируйте репозиторий и установите зависимости:**
   ```bash
   pip install -r requirements.txt
   ```

2. **(Опционально) Настройте свой VPS:**  
   Скопируйте шаблон `config.example.json` в `config.local.json` и укажите IP своего сервера и секретный путь админки:
   ```bash
   cp config.example.json config.local.json
   ```
   *(Файл `config.local.json` автоматически исключён из Git и никогда не улетит в публичный репозиторий).*

---

## 🚀 Быстрый запуск

### Вариант 1: Запуск через батник (Windows)
Просто запустите файл `radar.bat` двойным кликом мыши или в командной строке:
```cmd
.\radar.bat
```

### Вариант 2: Запуск через Python
```powershell
python reality_radar.py
```
*(Откроется интерактивное цветное меню с возможностью выбора любого действия).*

---

## 🛠️ Команды CLI

Вы можете использовать инструмент и без меню, передавая конкретные флаги:

| Команда | Описание |
| :--- | :--- |
| `python reality_radar.py scan` | Сканирование всех европейских доноров (NL + FI + LT + EU) |
| `python reality_radar.py scan --region fi` | Сканирование узлов Финляндии 🇫🇮 (Helsinki, CSC, FICIX, Yle) |
| `python reality_radar.py scan --region lt` | Сканирование узлов Литвы 🇱🇹 (Litnet, VU, KTU, LRT) |
| `python reality_radar.py scan --region nl` | Сканирование узлов Нидерландов 🇳🇱 (Serverius, Leaseweb, AMS-IX) |
| `python reality_radar.py scan --file domains.txt` | Сканирование собственного списка сайтов из текстового файла |
| `python reality_radar.py check <домен>` | Провести глубокий тест одного сайта (например: `csc.fi` или `vu.lt`) |
| `python reality_radar.py vps` | Запустить Sentinel-диагностику здоровья VPS и порта 443 |
| `python reality_radar.py tunnel start` | Поднять фоновый SSH-туннель к 3x-ui и открыть админку в браузере |
| `python reality_radar.py tunnel status` | Проверить, активен ли туннель к порту 5541 |
| `python reality_radar.py tunnel stop` | Остановить фоновый процесс туннеля |
| `python reality_radar.py qr "vless://..."` | Отрисовать ASCII QR-код для ключа подключения |

---

## 📊 Матрица скоринга доноров REALITY

- **PERFECT (85-100 баллов):** Поддержка TLS 1.3, протокол ALPN `h2`, прямой сервер без CDN, пинг < 60 мс. Рекомендован к боевому использованию.
- **GOOD (65-84 балла):** Валидный TLS 1.3/ALPN, стабильный отклик, чистый узел.
- **RISKY (30-64 балла):** Устаревший TLS 1.2 или нестабильный RTT. Повышенный риск внимания со стороны ТСПУ.
- **UNUSABLE (0-29 баллов):** Обнаружен Cloudflare / Akamai CDN, либо порт 443 заблокирован. Использование приведёт к блокировке или ошибкам 403.

---

## 📄 Лицензия

Распространяется свободно в общественном достоянии под лицензией [The Unlicense](LICENSE).
