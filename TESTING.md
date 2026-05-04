# Testing Guide

## Run locally

From repository root:

```bash
go test ./...
```

## CI

On each `push` and `pull_request`: [.github/workflows/ci-tests.yml](.github/workflows/ci-tests.yml).

## Coverage (current)

- iptables renderer: NAT chain split (`PREROUTING` vs `POSTROUTING`), DNAT direction handling

## Panel / API tests

Frontend and backend tests live in the **openvpn-control-server** repository.
