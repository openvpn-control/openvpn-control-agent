# Security

## Supported versions

Security fixes land on the default branch (`main` / `master`). No separate LTS line yet.

## Reporting a vulnerability

Do not open a public issue for undisclosed security problems until coordinated with maintainers.

1. Prefer [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) if enabled.
2. Otherwise use the security contact advertised for this repository.

Include: description, impact, component (HTTP API, token handling, firewall integration, etc.), steps to reproduce if safe, version/commit.

## Hardening (self-hosted agent)

- Do not expose the agent HTTP port to the internet without TLS and tight firewall rules; prefer reachability from the panel only (VPN/private network).
- Protect `AGENT_TOKEN_FILE`; rotate tokens if compromised.
- Run with least privilege; keep the binary and host OS updated.

Issues in the **web panel / API** belong to the separate **openvpn-control-server** repository.
