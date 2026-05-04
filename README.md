# OpenVPN Control Agent

Linux-агент для узла OpenVPN: HTTP API для панели, опрос **OpenVPN Management Interface**, метрики хоста, применение правил firewall/DNS по снимку с панели.

Панель управления — отдельный репозиторий **openvpn-control-server**.

**Лицензия:** [MIT](LICENSE) · **Безопасность:** [SECURITY.md](SECURITY.md) · **Вклад:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Сборка

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o openvpn-control-agent ./cmd/agent
```

Подробности (статическая линковка, glibc, установка): [BUILD-LINUX.md](BUILD-LINUX.md).

## Переменные окружения

- `AGENT_ADDR` — слушать (по умолчанию `:9443`)
- `OPENVPN_MGMT_ADDR` — management OpenVPN (по умолчанию `127.0.0.1:7505`)
- `AGENT_TOKEN_FILE` — файл токена (по умолчанию `/var/lib/openvpn-control-agent/token`)
- `OPENVPN_NET_INTERFACE` — опционально, например `tun0`

Токен создаётся при первом запуске; его нужно указать в панели при добавлении узла.

## Релизы (GitHub Actions)

1. `git tag v1.0.0 && git push origin v1.0.0`
2. **Releases → Create release** по тегу → **Publish release**
3. Воркфлоу **Release agent binaries** прикрепит `openvpn-control-agent-<тег>-linux-{amd64,arm64}` и `SHA256SUMS`.

**Settings → Actions → General:** для загрузки ассетов к релизу нужны права **Read and write** у `GITHUB_TOKEN`.

## Тесты

```bash
go test ./...
```

См. [.github/workflows/ci-tests.yml](.github/workflows/ci-tests.yml).

## Отказ от гарантий

ПО поставляется «как есть» ([LICENSE](LICENSE)).
