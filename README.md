# OpenVPN Control Agent

**Лицензия:** [MIT](LICENSE)

## Установка

Скачайте `.deb` или `.rpm` (amd64 / arm64) со [страницы релизов](https://github.com/openvpn-control/openvpn-control-agent/releases).

### Debian / Ubuntu (apt)

```bash
cd /path/to/download
sudo apt install ./openvpn-control-agent_<версия>_amd64.deb
sudo systemctl enable --now openvpn-control-agent
sudo systemctl status openvpn-control-agent --no-pager
```

Альтернатива без apt:

```bash
sudo dpkg -i openvpn-control-agent_<версия>_amd64.deb
sudo apt install -f   # при необходимости — зависимости
```

### RHEL / AlmaLinux / Rocky / Fedora (dnf / yum)

```bash
cd /path/to/download
sudo dnf install ./openvpn-control-agent-<версия>-1.x86_64.rpm
sudo systemctl enable --now openvpn-control-agent
sudo systemctl status openvpn-control-agent --no-pager
```

На системах без `dnf`:

```bash
sudo yum install ./openvpn-control-agent-<версия>-1.x86_64.rpm
```

### После установки

1. При необходимости отредактируйте `/etc/default/openvpn-control-agent` (порт, management OpenVPN).
2. Перезапустите службу: `sudo systemctl restart openvpn-control-agent`.
3. Токен для панели: `sudo cat /var/lib/openvpn-control-agent/token`.

Проверка на сервере:

```bash
curl -sS http://127.0.0.1:9443/health
```

С другой машины используйте **внешний IP** сервера, не `127.0.0.1`.

## Файрвол: порт 9443/tcp

Агент по умолчанию слушает **9443/tcp** (`AGENT_ADDR` в `/etc/default/openvpn-control-agent`). Откройте порт в ОС **и** в панели облачного провайдера (security group), если сервер в VPS.

### Debian / Ubuntu (ufw)

```bash
sudo ufw allow 9443/tcp comment 'openvpn-control-agent'
sudo ufw reload
sudo ufw status
```

### RHEL / AlmaLinux / Rocky / CentOS Stream / Fedora (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
```

### openSUSE (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload
```

### Если ufw и firewalld не используются (iptables)

```bash
sudo iptables -I INPUT -p tcp --dport 9443 -j ACCEPT
# сохраните правила способом, принятым в вашем дистрибутиве
```

Пример для Debian/Ubuntu с `iptables-persistent`:

```bash
sudo netfilter-persistent save
```

### Проверка доступа снаружи

На сервере:

```bash
ss -lntp | grep 9443
curl -sS --connect-timeout 3 http://$(curl -4 -s ifconfig.me):9443/health
```

С другой машины:

```bash
curl -v http://<внешний-IP-сервера>:9443/health
```

Если локально отвечает, а снаружи **No route to host** или timeout — чаще всего блокирует **firewalld/ufw** или **файрвол хостинга**, не сам агент.

## Переменные окружения

| Переменная | По умолчанию |
|------------|----------------|
| `AGENT_ADDR` | `:9443` |
| `AGENT_TOKEN_FILE` | `/var/lib/openvpn-control-agent/token` |
| `OPENVPN_MGMT_ADDR` | `127.0.0.1:7505` |
| `OPENVPN_NET_INTERFACE` | *(не задан)* |
