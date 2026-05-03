# VK PortScanner

## Что Это

`VK PortScanner` — асинхронный инструмент для мониторинга открытых портов на базе `masscan`.
Сканирует заданные цели, определяет сервисы и баннеры, проверяет уязвимости через `nmap` + `vulners`, сохраняет историю в SQLite и отправляет уведомления в Telegram и по email.

## Функции

- высокоскоростное сканирование через `masscan`
- асинхронный banner grabbing и определение сервиса
- проверка уязвимостей через `nmap` и `vulners`
- diff между сканированиями
- хранение данных в БД `SQLite`
- уведомления в Telegram
- уведомления по email
- запуск по расписанию через `APScheduler`

## Quick Start

1. Установить системные утилиты:

```bash
sudo apt update
sudo apt install masscan nmap
```

2. Выдать `masscan` нужные права:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/masscan
```

Альтернатива:

```bash
sudo /home/USERNAME/projects/vk-portscanner/.venv/bin/python3 main.py
```

3. Установить Python-зависимости:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Создать конфиг:

```bash
cp config.example.yaml config.yaml
```
При необходимости отредактировать.

5. Запустить:

```bash
source .venv/bin/activate
python3 main.py
```
