# Shisa (シーサー)

**Lightweight fleet management daemon for Linux**

Shisa is a fleet management tool for administering Linux machines over an encrypted TCP channel. It consists of a **Ruby control server** (interactive shell) and a **Crystal static binary client** (daemon on managed machines). All traffic is encrypted end-to-end using X25519 key exchange, Ed25519 mutual authentication, and ChaCha20-Poly1305 AEAD.

> **Disclaimer:** This tool is intended for authorized system administration and security testing only. Users are solely responsible for ensuring they have proper authorization before deploying to any system. The authors assume no liability for misuse or damage caused by this software. Use responsibly and in compliance with applicable laws and policies.

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Security & Encryption](#security--encryption)
- [Fleet Management](#fleet-management)
- [Filesystem Operations](#filesystem-operations)
- [Remote Execution](#remote-execution)
- [System Administration](#system-administration)
- [Network & Tunnels](#network--tunnels)
- [Monitoring & Observability](#monitoring--observability)
- [Package Management](#package-management)
- [Scripting & Automation](#scripting--automation)
- [Daemon Lifecycle](#daemon-lifecycle)
- [Deployment](#deployment)
- [Building from Source](#building-from-source)
- [Command Reference](#command-reference)

---

## Architecture

```
┌─────────────────────────────┐          ┌──────────────────────────────┐
│       Control Server        │          │        Client Daemon         │
│         (Ruby)              │◄────────►│         (Crystal)            │
│                             │ Encrypted│                              │
│  server.rb                  │   TCP    │  client.cr                   │
│  ├── src/services.rb        │          │  ├── src/protocol.cr         │
│  │   (Protocol::Envelope)   │          │  │   (Envelope + Dispatcher) │
│  ├── src/transport.rb       │          │  ├── src/handlers/commands.cr│
│  │   (SocketServer + X25519)│          │  │   (all event handlers)    │
│  ├── src/diffie.rb          │          │  ├── src/handlers/tunnel.cr  │
│  │   (X25519 + Ed25519)     │          │  │   (tunnel relay)          │
│  ├── src/shell.rb           │          │  ├── src/crypto/curve25519.cr│
│  │   (interactive REPL)     │          │  │   (OpenSSL FFI bindings)  │
│  ├── src/storage.rb         │          │  ├── src/tunnel/session.cr   │
│  │   (db/ + logs/ JSON)     │          │  │   (X25519 + ChaCha20)    │
│  └── src/tunnel_server.rb   │          │  └── src/utils/sysinfo.cr    │
│      (-L/-R forwarding)     │          │      (hardware/OS inventory) │
└─────────────────────────────┘          └──────────────────────────────┘
```

**Protocol**: Every message is a JSON envelope `{event, id?, payload?}` encrypted with ChaCha20-Poly1305 and framed with a 4-byte big-endian length prefix. The `id` field enables request-reply correlation.

**Identity**: Each client generates a stable **HWID** (hardware ID) from DMI product UUID, machine-id, or a fingerprint of hardware attributes. HWIDs survive reboots, reconnects, and binary updates.

---

## Quick Start

### 1. Generate Keys

```bash
ruby keys/generate.rb
```

Creates server and client Ed25519 keypairs. See [SETUP.md](SETUP.md) for details.

### 2. Start the Server

```bash
ruby server.rb [port]
# Default port: 32435
```

### 3. Build and Deploy a Client

```bash
# Automated build (recommended)
ruby tools/build_client.rb \
  --host 10.0.0.1:32435 \
  --server-key $(cat keys/server.pub) \
  --register --static --upx

# Or manual build
crystal build client.cr -o shisa-client --release --static
```

### 4. First Session

```
shisa> who
     HWID         HOST                 HOSTNAME     USER       OS                 PING     UPTIME
  ----------------------------------------------------------------------------------------------------------
  *  a1b2c3d4e5f6 203.0.113.10:48231   web-prod-01  root       Fedora Linux 44    12.3ms   2h 15m
     f7e8d9c0b1a2 198.51.100.5:39122   db-staging   oak        Ubuntu 24.04       45.1ms   6d 3h

  2 client(s) connected

shisa> use web-prod
  selected a1b2c3d4e5 (web-prod-01)

[web-prod-01]> top
  Uptime: 2h 15m    Load: 0.45 0.62 0.71    CPUs: 4

  CPU:  [████████░░░░░░░░░░░░]  38.2%
  Mem:  [██████████████░░░░░░]  71.4%  (5.7 GB / 8.0 GB)

  Disk:
    /              [████████████░░░░]  60.1%  (32G / 50G)

[web-prod-01]> back
shisa>
```

---

## Security & Encryption

### Key Exchange and Authentication

1. Client and server exchange **X25519** ephemeral public keys (32 bytes each)
2. Shared secret is derived via **HKDF-SHA256** into two 32-byte keys (`c2s` + `s2c`)
3. Server sends an **Ed25519 AUTH_CHALLENGE** (encrypted) ; proves server identity
4. Client verifies against compiled-in `TRUSTED_SERVER_KEYS`, then sends **AUTH_RESPONSE**
5. Server verifies against `keys/authorized_clients/*.pub`

Authentication happens inside the encrypted channel ; Ed25519 public keys are never exposed in plaintext. The auth transcript binds to the X25519 session with role separation (server=0x01, client=0x02) to prevent reflection and replay attacks.

### Symmetric Encryption

- **Cipher**: ChaCha20-Poly1305 (RFC 8439)
- **Nonce**: 12-byte, monotonically increasing counter
- **Replay protection**: Receiver enforces strictly-increasing nonces
- **Wire format**: `nonce (12B) || ciphertext || tag (16B)`, length-prefixed with 4-byte big-endian header

### Client Identity

Each client binary has a unique Ed25519 keypair compiled in at build time. The server only accepts connections from clients whose public keys are registered. This ensures every deployed binary was issued by the operator.

### Keepalive

The server pings every **25 seconds**; clients that miss 3 cycles (75s) are disconnected. The client runs a receive watchdog ; if no data arrives for **45 seconds**, it assumes the connection is dead and enters the reconnect loop.

---

## Fleet Management

### Selecting Clients

```bash
shisa> use a1b2c3          # HWID prefix
shisa> use web-prod         # hostname prefix
shisa> use web01            # alias
shisa> use @production      # group (targets all members)
[web-prod-01]> back         # deselect
```

Resolution order: alias → HWID exact/prefix → hostname exact/prefix → socket ID fallback.

### Groups

```bash
shisa> group create production
shisa> group add production web01
shisa> group add production web02

shisa> use @production
[@production (2)]> exec uptime
  [a1b2c3d4] 10:23:15 up 45 days, ...
  [f7e8d9c0] 10:23:15 up 12 days, ...
```

### Aliases and Notes

```bash
shisa> alias set web01 a1b2c3d4e5f6
shisa> note set web01 production load balancer, do not reboot without approval
```

Notes appear in the `who` listing beneath each client.

---

## Filesystem Operations

```bash
[web-prod-01]> ls /var/log
  drwxr-xr-x  root root  4.0K  nginx/
  -rw-r-----  root adm   2.4M  syslog
  -rw-r-----  root adm   150K  auth.log

[web-prod-01]> cat /var/log/auth.log
[web-prod-01]> edit /etc/nginx/nginx.conf    # opens in $EDITOR, uploads on save

# File management
[web-prod-01]> mkdir /opt/deploy
[web-prod-01]> cp -r /etc/nginx /etc/nginx.bak
[web-prod-01]> mv /tmp/config.new /etc/app/config.yml
[web-prod-01]> chmod 755 /opt/deploy/run.sh
[web-prod-01]> rm -r /tmp/old-build

# File transfer ; single file, glob, or directory
[web-prod-01]> download /var/log/nginx/*.log ./logs/
  downloading 4 file(s)...
  [1/4] access.log
  [2/4] error.log
  ...
  downloaded 4/4 file(s) -> ./logs/

[web-prod-01]> upload ./configs/ /etc/app/
  uploading 3 file(s)...
  uploaded 3/3 file(s) -> /etc/app/
```

File transfers use **64KB chunks** with SHA256 integrity verification.

---

## Remote Execution

### One-shot Commands

```bash
[web-prod-01]> exec systemctl status nginx

# Across a group ; results labeled by HWID
[@production (3)]> exec df -h /
```

### Interactive Shell

```bash
[web-prod-01]> shell
  shell opened (Ctrl+D to close)
$ whoami
root
$ ^D
  shell closed
```

### In-Memory Scripts (memfile)

Scripts that live only in the client's RAM ; never touch disk.

```bash
[web-prod-01]> memfile edit recon          # opens $EDITOR, content goes to client RAM
[web-prod-01]> memfile exec recon bash     # run with interpreter
[web-prod-01]> memfile list
[web-prod-01]> memfile delete recon
```

---

## System Administration

### System Info

```bash
[web-prod-01]> top         # CPU, memory, swap, disk with bar charts
[web-prod-01]> ps nginx    # process listing with optional filter
[web-prod-01]> df          # disk space usage
[web-prod-01]> free        # memory usage
[web-prod-01]> du /var/log # directory size
[web-prod-01]> info        # full 30+ field sysinfo report
```

### Service Management

```bash
[web-prod-01]> service list nginx
[web-prod-01]> service restart nginx.service
[web-prod-01]> service enable nginx.service

# Install shisa-client as a systemd service
[web-prod-01]> service install --name shisa --user root
```

### Privilege Escalation

```bash
[web-prod-01]> escalate sudo       # restart as root via sudo
[web-prod-01]> escalate su         # restart as root via su
[web-prod-01]> escalate setuid     # set SUID bit and restart
```

### Client Update

Push an updated binary to a client's install path:

```bash
[web-prod-01]> update ./shisa-client-v2
  pushing ./shisa-client-v2 -> /usr/local/bin/shisa (4.2 MB)
  This will overwrite the running binary. Continue? [y/N] y
  updated. Client must be restarted to use the new version.
```

### Cron Management

```bash
[web-prod-01]> cron list
[web-prod-01]> cron add 0 2 * * * /usr/local/bin/cleanup.sh
[web-prod-01]> cron remove 2
```

---

## Network & Tunnels

### Network Info

```bash
[web-prod-01]> ifconfig        # interfaces, addresses, traffic counters
[web-prod-01]> netstat          # listening sockets (also: established, all, udp)
[web-prod-01]> route            # routing table
```

### Port Forwarding

SSH-style tunnel forwarding through the encrypted channel.

```bash
# Local: server listens, forwards to host reachable by client
[web-prod-01]> forward -L 3307:127.0.0.1:3306
  tunnel #1: server:3307 -> 127.0.0.1:3306 via a1b2c3d4

# Remote: client listens, forwards to host reachable by server
[web-prod-01]> forward -R 9090:127.0.0.1:8080
  tunnel #2: client:9090 -> 127.0.0.1:8080 via a1b2c3d4

# Manage
[web-prod-01]> tunnels
[web-prod-01]> tunnel close 1
```

### Route Management

Wrapper around `ip route` with safety guardrails ; warns before modifying the default route or routes that carry the client's connection.

```bash
[web-prod-01]> route add 172.16.0.0/12 via 10.0.0.1
[web-prod-01]> route del 172.16.0.0/12
```

---

## Monitoring & Observability

### Watch Mode

```bash
[web-prod-01]> watch -n 5 df -h /     # repeat every 5s, Ctrl+C to stop
```

### Session Monitoring

```bash
[web-prod-01]> sessions                       # list logged-in users
[web-prod-01]> sessions write pts/0 Maintenance in 10 minutes
[web-prod-01]> sessions kill pts/1            # kill all processes on a tty
[web-prod-01]> sessions listen pts/0          # spy on terminal output (strace)
```

### Journal / Syslog

```bash
[web-prod-01]> journal -u nginx -p err --since "1 hour ago"
[web-prod-01]> journal -g "connection refused" -n 50
```

### Login Monitoring

The client automatically monitors user logins/logouts and sends real-time events:

```
[+user] oak logged in on web-prod-01 (pts/0)
[-user] admin logged out from web-prod-01 (pts/1)
```

---

## Package Management

Auto-detects the client's package manager (dnf, apt-get, pacman, zypper).

```bash
[web-prod-01]> pkg list
[web-prod-01]> pkg search htop
[web-prod-01]> pkg install htop       # requires confirmation
[web-prod-01]> pkg remove htop
[web-prod-01]> pkg update             # update index
[web-prod-01]> pkg upgrade            # upgrade all packages
[web-prod-01]> pkg info nginx
```

Works across groups ; `[@production]> pkg list` queries all members in parallel.

---

## Scripting & Automation

### Script Macros

Record commands and replay them later. Scripts can include context switches (`use`/`back`) to orchestrate across multiple clients.

```bash
shisa> script record deploy-web
[REC] shisa> use web01
[REC] [web-prod-01]> exec systemctl stop nginx
[REC] [web-prod-01]> upload ./nginx.conf /etc/nginx/nginx.conf
[REC] [web-prod-01]> exec systemctl start nginx
[REC] [web-prod-01]> back
[REC] shisa> script stop
  saved script 'deploy-web' (4 commands)

shisa> script run deploy-web
```

### Client-to-Client Transfer

Copy files between connected clients ; supports glob patterns and directories.

```bash
shisa> scp web01:/var/log/*.log db01:/tmp/logs/
  transferring 4 file(s): web01:/var/log/*.log -> db01:/tmp/logs/
  transferred 4/4 file(s)
```

### Key Management

Reload authorized client keys without restarting the server:

```bash
shisa> refresh
  reloaded 5 authorized client keys from keys/authorized_clients/
```

---

## Daemon Lifecycle

### Multi-Server Failover

The client supports multiple control servers, tried in order:

```crystal
SERVERS = [
  {host: "primary.example.com", port: 32435},
  {host: "primary.example.com", port: 443},
  {host: "backup.example.com", port: 22},
]
```

If `RESPECT_TRIES` is true (default), each server gets 3 attempts before failover. After all servers are exhausted, the client backs off for 5 minutes before restarting the cycle. This handles restricted networks (try port 443, then 22) and primary/backup redundancy.

### Migrate and Persist

```bash
[web-prod-01]> migrate /usr/local/bin/shisa     # move binary, re-exec from new path
[web-prod-01]> service install --name shisa      # install as systemd service
[web-prod-01]> service enable shisa
[web-prod-01]> service start shisa
```

### Other Controls

```bash
[web-prod-01]> restart         # re-exec the daemon binary
[web-prod-01]> daemonize       # detach from terminal (setsid)
[web-prod-01]> kill-daemon     # terminate with no restart
```

---

## Deployment

### Recommended Workflow

```bash
# 1. Build a client for the target
ruby tools/build_client.rb \
  --host control.example.com:32435 \
  --server-key $(cat keys/server.pub) \
  --register --static --upx \
  --output shisa-client

# 2. Transfer and start
scp shisa-client user@target:/tmp/
ssh user@target '/tmp/shisa-client &'

# 3. On the control server
shisa> who                                      # client appears
shisa> use <client>
[target]> escalate sudo                          # get root
[target]> migrate /usr/local/bin/shisa           # move to system path
[target]> service install --name shisa           # persist as service
[target]> service enable shisa
[target]> service start shisa
```

---

## Building from Source

### Requirements

- **Server**: Ruby 3.x with OpenSSL
- **Client**: Crystal 1.x with OpenSSL development headers

### Build Options

```bash
# Development
crystal build client.cr -o shisa-client

# Release
crystal build client.cr -o shisa-client --release --no-debug

# Static (via Docker)
ruby tools/build_client.rb --host <host> --server-key <key> --static

# Static + UPX compressed
ruby tools/build_client.rb --host <host> --server-key <key> --static --upx
```

See [SETUP.md](SETUP.md) for complete setup instructions including key generation and builder options.

---

## Command Reference

### Global Commands

| Command | Description |
|---------|-------------|
| `use <id\|alias\|@group>` | Select a client or group |
| `who` / `list` | Show connected clients |
| `broadcast <message>` | Send message to all clients |
| `kick <id>` | Disconnect a client |
| `group create\|delete\|add\|remove\|list` | Manage groups |
| `alias set\|remove\|list` | Manage aliases |
| `note set\|remove` | Client notes |
| `history [N]` | Command history |
| `script record\|stop\|run\|show\|list\|delete` | Macro management |
| `scp <src>:<path> <dst>:<path>` | Client-to-client transfer (glob/dir) |
| `refresh` | Reload authorized client keys |
| `help` | Show help |
| `quit` | Exit |

### Client Commands

| Category | Command | Description |
|----------|---------|-------------|
| **Filesystem** | `cd`, `pwd`, `ls`, `cat`, `edit` | Navigate and view |
| | `mkdir`, `rm`, `mv`, `cp`, `chmod` | File management |
| | `download`, `upload` | Transfer (glob/dir support) |
| | `update <local-file>` | Push file to client install path |
| **Exec** | `exec <cmd>` | Run shell command |
| | `shell` | Interactive bash session |
| **Memfile** | `memfile edit\|upload\|exec\|cat\|list\|delete` | In-memory scripts |
| **Cron** | `cron list\|add\|remove` | Crontab management |
| **System** | `ps`, `top`, `df`, `free`, `du` | System info |
| | `reboot`, `shutdown` | Power management |
| | `restart`, `migrate`, `daemonize`, `kill-daemon` | Daemon lifecycle |
| | `escalate sudo\|su\|setuid\|script` | Privilege escalation |
| **Services** | `service list\|status\|start\|stop\|restart\|enable\|disable\|install` | Systemd |
| **Network** | `ifconfig`, `netstat` | Network info |
| | `forward -L\|-R`, `tunnels`, `tunnel close` | Port forwarding |
| | `route show\|add\|del\|replace` | Routing with guardrails |
| **Monitor** | `watch [-n sec] <cmd>` | Periodic execution |
| | `sessions list\|kill\|write\|listen` | User session management |
| | `journal [options]` | Systemd journal query |
| | `find [path] [options]` | Remote file search |
| **Packages** | `pkg list\|search\|install\|remove\|update\|upgrade\|info` | Package management |

### Data Storage

| Path | Contents |
|------|----------|
| `db/groups.json` | Client groups |
| `db/aliases.json` | Client aliases |
| `db/notes.json` | Per-client notes |
| `db/scripts.json` | Command macros |
| `logs/dd-mm-yyyy.json` | Daily command history and events |
