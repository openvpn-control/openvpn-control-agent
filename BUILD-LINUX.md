# Сборка и установка openvpn-control-agent (Linux)

Агент собирается под Linux как **полностью статический** исполняемый файл (`CGO_ENABLED=0`), без привязки к версии **glibc** на машине сборки — такой бинарник запускается и на Ubuntu 20.04 (glibc 2.31), и на более новых дистрибутивах. Он слушает HTTP (по умолчанию `:9443`), читает метрики хоста и опрашивает OpenVPN через management-интерфейс.

## Требования

- **Go** не ниже **1.22** (см. `go.mod`).
- **OpenVPN** с включённым management-сокетом (по умолчанию агент ждёт `127.0.0.1:7505` — задайте `OPENVPN_MGMT_ADDR`, если у вас другой адрес).
- Доступ с панели управления к порту агента (часто **9443/tcp**), если сервер не на localhost.

## Сборка из исходников (Linux)

**Важно:** собирайте с **`CGO_ENABLED=0`**. Иначе линкер подтянет **glibc** той версии, что на машине сборки (например 2.34), и на **Ubuntu 20.04** появится ошибка вида `version 'GLIBC_2.32' not found`.

Из корня этого репозитория:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
```

Проверка, что бинарник не тянет системный libc:

```bash
ldd openvpn-control-agent
# ожидается: not a dynamic executable
```

Проверка версии компилятора:

```bash
go version
```

Сборка под другую архитектуру (пример: **amd64** на машине-сборщике):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
```

Другие значения `GOARCH`: `arm64`, `386` и т.д.

Установка бинарника вручную:

```bash
sudo install -m 755 openvpn-control-agent /usr/local/bin/openvpn-control-agent
```

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|------------|----------------|------------|
| `AGENT_ADDR` | `:9443` | Адрес прослушивания HTTP (`:порт` или `host:port`) |
| `AGENT_TOKEN_FILE` | `/var/lib/openvpn-control-agent/token` | Файл с токеном (`X-Agent-Token`); при первом запуске создаётся автоматически |
| `OPENVPN_MGMT_ADDR` | `127.0.0.1:7505` | Адрес management OpenVPN |
| `OPENVPN_NET_INTERFACE` | *(пусто)* | Интерфейс для учёта трафика (если нужен явно) |

После первого запуска прочитайте токен из `AGENT_TOKEN_FILE` и зарегистрируйте узел в панели управления с тем же значением.

---

## Debian / Ubuntu

### 1. Установка Go (если версии из репозитория недостаточно)

Вариант A — пакет дистрибутива (удобно, но версия может быть старее 1.22):

```bash
sudo apt update
sudo apt install -y golang-go build-essential
go version
```

Вариант B — официальный дистрибутив Go с [go.dev/dl](https://go.dev/dl/) (распаковать в `/usr/local/go`, добавить `PATH`).

### 2. Сборка

```bash
cd /path/to/openvpn-control-agent
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
sudo install -m 755 openvpn-control-agent /usr/local/bin/openvpn-control-agent
```

### 3. Каталог для токена

```bash
sudo install -d -m 755 /var/lib/openvpn-control-agent
```

### 4. systemd

Создайте `/etc/default/openvpn-control-agent`:

```bash
# Слушать на всех интерфейсах (пример)
AGENT_ADDR=0.0.0.0:9443
AGENT_TOKEN_FILE=/var/lib/openvpn-control-agent/token
OPENVPN_MGMT_ADDR=127.0.0.1:7505
# OPENVPN_NET_INTERFACE=tun0
```

Создайте `/etc/systemd/system/openvpn-control-agent.service`:

```ini
[Unit]
Description=OpenVPN Control Agent
After=network-online.target openvpn.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/openvpn-control-agent
ExecStart=/usr/local/bin/openvpn-control-agent
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Зависимость `openvpn.service` укажите, только если юнит OpenVPN у вас так называется; иначе уберите или замените.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-control-agent
sudo systemctl status openvpn-control-agent --no-pager
```

Журнал:

```bash
journalctl -u openvpn-control-agent -f
```

### 5. Файрвол (при необходимости)

```bash
sudo ufw allow 9443/tcp
sudo ufw reload
```

---

## Red Hat Enterprise Linux / CentOS Stream / AlmaLinux / Rocky Linux

### 1. Установка Go

**AlmaLinux / Rocky / RHEL / CentOS Stream** (пакет `golang`):

```bash
sudo dnf install -y golang gcc
go version
```

Если версия Go ниже 1.22, поставьте свежий Go с [go.dev/dl](https://go.dev/dl/) или используйте модуль Go в RHEL (`dnf module list golang`), если доступен.

### 2. Сборка и установка бинарника

```bash
cd /path/to/openvpn-control-agent
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
sudo install -m 755 openvpn-control-agent /usr/local/bin/openvpn-control-agent
sudo install -d -m 755 /var/lib/openvpn-control-agent
```

### 3. systemd

Файлы такие же, как в разделе **Debian / Ubuntu**: `/etc/default/openvpn-control-agent` и `/etc/systemd/system/openvpn-control-agent.service`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-control-agent
sudo systemctl status openvpn-control-agent --no-pager
```

### 4. Файрвол (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload
```

### 5. SELinux

Если агент слушает нестандартный порт или каталог с токеном в необычном месте, при отказах в логах смотрите `audit2why` / контексты. Для типовой установки на `9443` и `/var/lib/openvpn-control-agent` часто достаточно настроек по умолчанию.

---

## Ошибка `GLIBC_2.32` / `GLIBC_2.34` not found (Ubuntu 20.04 и др.)

Сообщение значит: бинарник собран **с привязкой к новой glibc** (часто из‑за сборки с **CGO** на свежем дистрибутиве), а на целевой системе glibc старее (у **Ubuntu 20.04** — **2.31**).

**Исправление:** пересоберите агент с отключённым CGO и замените файл на сервере:

```bash
cd /path/to/openvpn-control-agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
sudo systemctl stop openvpn-control-agent
sudo install -m 755 openvpn-control-agent /usr/local/bin/openvpn-control-agent
sudo systemctl start openvpn-control-agent
```

Альтернатива: собирать **на самой Ubuntu 20.04** (тогда даже с CGO бинарник будет совместим с её glibc), но для релизов надёжнее везде использовать **`CGO_ENABLED=0`**.

---

## Проверка работы

На машине с агентом (подставьте токен из `AGENT_TOKEN_FILE`):

```bash
curl -sS -H "X-Agent-Token: ВАШ_ТОКЕН" "http://127.0.0.1:9443/health"
curl -sS -H "X-Agent-Token: ВАШ_ТОКЕН" "http://127.0.0.1:9443/metrics"
```

Ожидается JSON без ошибки **401** (неверный или отсутствующий заголовок `X-Agent-Token`).
