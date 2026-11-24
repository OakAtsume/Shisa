# Glob-VM Documentation

**Centralized Lab Computer Management System**

Glob-VM is a fleet management tool for administering Linux machines over an encrypted TCP channel. It consists of a **Ruby control server** (interactive shell) and a **Crystal daemon** (runs on managed machines). All traffic is encrypted end-to-end using Diffie-Hellman key exchange and ChaCha20-Poly1305.

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
│  │   (SocketServer + DH)    │          │  │   (all event handlers)    │
│  ├── src/shell.rb           │          │  ├── src/handlers/tunnel.cr  │
│  │   (interactive REPL)     │          │  │   (tunnel relay)          │
│  ├── src/tunnel_server.rb   │          │  ├── src/utils/sysinfo.cr    │
│  │   (-L/-R forwarding)     │          │  │   (hardware/OS inventory) │
│  ├── src/storage.rb         │          │  ├── src/tunnel/session.cr   │
│  │   (JSON persistence)     │          │  │   (DH + ChaCha20)        │
│  └── src/diffie.rb          │          │  └── src/utils/tcpsock.cr    │
│      (DH + ChaCha20)        │          │      (TCP socket manager)    │
└─────────────────────────────┘          └──────────────────────────────┘
```

**Protocol**: Every message is a JSON envelope `{event, id?, payload?}` encrypted with ChaCha20-Poly1305 and framed with a 4-byte big-endian length prefix. The `id` field enables request-reply correlation — the server blocks on a reply queue keyed by `id`, and the client dispatches responses back with the same `id`.

**Identity**: Each client generates a stable **HWID** (hardware ID) from DMI product UUID, machine-id, or a fingerprint of hardware attributes. HWIDs survive reboots, reconnects, and binary updates, so groups, aliases, and notes persist across sessions.

---

## Quick Start

### Starting the Server

```bash
ruby server.rb [port]
# Default port: 32435
```

The server starts an encrypted TCP listener and drops into an interactive shell. All connected clients appear in the `who` listing.

### Deploying the Client

```bash
# Compile (requires Crystal)
crystal build client.cr -o glob-client --release

# Or build a portable static binary (requires Docker)
./build-static.sh glob-client

# Run the daemon
./glob-client
```

The client connects, performs a Diffie-Hellman handshake, sends system information, and begins accepting commands. If the connection drops, it automatically reconnects with exponential backoff (3 retries at 3s intervals, then 5-minute cooldown).

### First Session Example

```
glob> who
     HWID         HOST                 HOSTNAME     USER       OS                 PING     UPTIME
  ----------------------------------------------------------------------------------------------------------
  *  a1b2c3d4e5f6 203.0.113.10:48231   web-prod-01  root       Fedora Linux 44    12.3ms   2h 15m
     f7e8d9c0b1a2 198.51.100.5:39122   db-staging   oak        Ubuntu 24.04       45.1ms   6d 3h

  2 client(s) connected

glob> alias set web01 a1b2c3d4e5f6
  set alias web01 -> a1b2c3d4e5f6

glob> use web01
  selected a1b2c3d4e5 (web-prod-01)

[web-prod-01]> ps nginx
  PID    USER     %CPU  %MEM  VSZ       RSS      TTY   STAT  START  TIME   COMMAND
  1234   root     0.0   0.2   45312     8192     ?     Ss    Oct28  0:05   nginx: master process
  1235   www-data 0.1   0.4   46080     16384    ?     S     Oct28  1:23   nginx: worker process

[web-prod-01]> back
glob>
```

---

## Security & Encryption

### Handshake

1. Client connects via TCP
2. Both sides generate ephemeral DH key pairs (MODP group, 256-byte public keys)
3. Public keys are exchanged in the clear (256 bytes each)
4. Shared secret is derived and expanded via **HKDF-SHA256** into two 32-byte keys:
   - `c2s` — client-to-server encryption key
   - `s2c` — server-to-client encryption key
5. Degenerate keys (0, 1, p-1) are rejected to prevent known-secret attacks

### Encryption

- **Cipher**: ChaCha20-Poly1305 (RFC 8439)
- **Nonce**: 12-byte, monotonically increasing counter (4 zero bytes + 8-byte big-endian)
- **Authentication**: 16-byte Poly1305 tag on every message
- **Replay protection**: Receiver enforces strictly-increasing nonces; any out-of-order or replayed nonce is rejected
- **Wire format**: `nonce (12B) || ciphertext || tag (16B)`, length-prefixed with 4-byte big-endian header

### Keepalive

The server sends a `ping` every **25 seconds**. If no `pong` is received within **75 seconds**, the client is disconnected. The client runs a **receive watchdog** — if no data arrives from the server for **45 seconds** (missed two ping cycles), it assumes the connection is dead, closes the socket, and enters the reconnect loop. This handles laptop sleep, network drops, and silent server crashes.

---

## Fleet Management

### Client Identification

Every client is identified by its **HWID**, a stable SHA256 hash derived from (in priority order):
1. DMI product UUID (`/sys/class/dmi/id/product_uuid`)
2. Machine ID (`/etc/machine-id`)
3. Fingerprint of hostname + vendor + product + board + architecture

The HWID persists across reboots, reconnects, IP changes, and binary updates.

### Selecting Clients

```bash
# By HWID (prefix match)
glob> use a1b2c3

# By hostname (prefix match)
glob> use web-prod

# By alias
glob> use web01

# By group (targets all members simultaneously)
glob> use @production

# Deselect
[web-prod-01]> back
```

Resolution order: alias → HWID exact/prefix → hostname exact/prefix → socket ID fallback.

### The `who` / `list` Display

```
glob> who
     HWID         HOST                 HOSTNAME     USER       OS                 PING     UPTIME
  ----------------------------------------------------------------------------------------------------------
  *  a1b2c3d4e5f6 203.0.113.10:48231   web-prod-01  root       Fedora Linux 44    12.3ms   2h 15m
     alias:web01 | production server
     f7e8d9c0b1a2 198.51.100.5:39122   db-staging   oak        Ubuntu 24.04       45.1ms   6d 3h

  2 client(s) connected
```

- **HWID**: Stable hardware identifier (first 12 chars)
- **HOST**: Remote IP:port of the TCP connection
- **HOSTNAME**: OS hostname from sysinfo
- **USER**: Detected from `SUDO_USER` environment variable
- **OS**: Distribution name and version
- **PING**: RTT latency, color-coded (green <50ms, yellow <150ms, red 150ms+)
- **UPTIME**: Duration since the client established its session
- **Subline**: Alias and/or note if set

### Groups

Groups let you target multiple clients with a single command. Members are stored by HWID, so they survive reconnects.

```bash
# Create and populate a group
glob> group create production
glob> group add production web01
glob> group add production web02
glob> group add production web03

# Target the group — commands run on all members simultaneously
glob> use @production
[@production (3)]> exec uptime
  [a1b2c3d4] 10:23:15 up 45 days, ...
  [f7e8d9c0] 10:23:15 up 12 days, ...
  [c3d4e5f6] 10:23:15 up 3 days, ...

# List groups and members
glob> group list

# Remove a member
glob> group remove production web03

# Delete the group
glob> group delete production
```

### Aliases

Friendly names for HWIDs. Aliases are checked first in the resolution chain.

```bash
glob> alias set db01 f7e8d9c0b1a2
glob> alias set web01 a1b2c3d4e5f6
glob> alias list
glob> alias remove db01
```

### Notes

Attach freeform text to any client.

```bash
glob> use web01
[web-prod-01]> note set production load balancer, DO NOT reboot without approval
[web-prod-01]> note remove
```

Notes appear in the `who` listing beneath each client.

### Detailed Client Info

```bash
[web-prod-01]> info
  hostname           web-prod-01
  hwid               a1b2c3d4e5f6789...
  os_name            Fedora Linux
  os_version         44
  kernel_release     6.8.5-301.fc40.x86_64
  architecture       x86_64
  system_vendor      Dell Inc.
  product_name       PowerEdge R640
  local_addresses    192.168.1.10, 10.0.0.5
  pid                1234
  sudo_user          oak
  ...
```

Shows every field from the client's sysinfo report (30+ fields covering process, identity, OS, hardware, and network).

---

## Filesystem Operations

All filesystem commands operate relative to a tracked working directory on the client (not the OS process CWD).

```bash
[web-prod-01]> pwd
  /home/oak

[web-prod-01]> cd /var/log
[web-prod-01]> ls
  auth.log    kern.log    syslog    nginx/    mysql/

[web-prod-01]> cat nginx/error.log
  2024/10/28 10:23:15 [error] ...

# Edit a remote file — downloads, opens in $EDITOR, uploads changes back
[web-prod-01]> edit /etc/nginx/nginx.conf

# File transfer with SHA256 verification and progress bar
[web-prod-01]> download /etc/nginx/nginx.conf ./nginx.conf.bak
  downloading... [████████████████████] 100% 2.4 KB
  saved ./nginx.conf.bak (sha256 verified)

[web-prod-01]> upload ./new-config.conf /etc/nginx/nginx.conf
  uploading... [████████████████████] 100% 2.4 KB
  written /etc/nginx/nginx.conf (sha256 verified)
```

File transfers use **64KB chunks** with SHA256 integrity verification. Files larger than 1MB are rejected by `cat` (use `download` instead).

---

## Remote Execution

### One-shot Commands

```bash
# Single client
[web-prod-01]> exec systemctl status nginx

# Across a group — results are labeled by HWID prefix
[@production (3)]> exec df -h /
  [a1b2c3d4] Filesystem   Size  Used  Avail  Use%  Mounted on
  [a1b2c3d4] /dev/sda1    50G   32G   18G    64%   /
  [f7e8d9c0] /dev/sda1    100G  45G   55G    45%   /
  [c3d4e5f6] /dev/sda1    50G   48G   2G     96%   /
```

### Interactive Shell

Opens a live bash session with piped stdin/stdout/stderr. Behaves like SSH.

```bash
[web-prod-01]> shell
  shell opened (Ctrl+D to close)
$ whoami
root
$ ls -la /tmp
...
$ ^D
  shell closed
```

### In-Memory Scripts (memfile)

Scripts that live **only in the client's RAM** — they never touch disk. Useful for sensitive payloads, one-time scripts, or volatile tooling.

```bash
# Create from your local editor
[web-prod-01]> memfile edit recon
  # Opens $EDITOR, content sent to client RAM on save

# Or upload a local file
[web-prod-01]> memfile upload ./local-script.sh recon

# Execute with an interpreter
[web-prod-01]> memfile exec recon bash
[web-prod-01]> memfile exec scanner python3

# Manage
[web-prod-01]> memfile list
  NAME         SIZE
  recon        1.2 KB
  scanner      4.5 KB

[web-prod-01]> memfile cat recon
[web-prod-01]> memfile delete recon
```

### Cron Management

```bash
[web-prod-01]> cron list
  #  SCHEDULE              COMMAND
  1  0 * * * *             /usr/local/bin/backup.sh
  2  */5 * * * *           /usr/local/bin/health-check.sh

[web-prod-01]> cron add 0 2 * * * /usr/local/bin/cleanup.sh
  added cron entry

[web-prod-01]> cron remove 2
  removed entry #2

# List across a group
[@production (3)]> cron list
```

---

## System Administration

### Process Management

```bash
# Process listing with optional filter
[web-prod-01]> ps nginx
  PID    USER     %CPU  %MEM  VSZ       RSS      TTY   STAT  START  TIME   COMMAND
  1234   root     0.0   0.2   45312     8192     ?     Ss    Oct28  0:05   nginx: master
  1235   www-data 0.1   0.4   46080     16384    ?     S     Oct28  1:23   nginx: worker

# System overview with bar charts
[web-prod-01]> top
  CPU:     [████████░░░░░░░░░░░░]  38.2%
  Memory:  [██████████████░░░░░░]  71.4%  (5.7 GB / 8.0 GB)
  Swap:    [░░░░░░░░░░░░░░░░░░░░]   0.0%  (0 B / 2.0 GB)
  Load:    0.45  0.62  0.71
  Uptime:  45 days, 2:15:03

  DISK         SIZE    USED    AVAIL   USE%
  /            50G     32G     18G     64%
  /home        100G    45G     55G     45%
```

### Power Management

```bash
# Requires confirmation
[web-prod-01]> reboot
  Reboot web-prod-01? [y/N] y
  reboot signal sent

[web-prod-01]> shutdown
  SHUTDOWN web-prod-01? This is irreversible! [y/N] y
  shutdown signal sent
```

### Privilege Escalation

Restart the daemon with elevated privileges — solves the `echo pw | sudo -S` crash by using proper stdin pipe management.

```bash
# Restart as root via sudo (password prompt is hidden)
[web-prod-01]> escalate sudo
  Password: ********
  escalating via sudo

# Restart as root via su
[web-prod-01]> escalate su
  Password: ********
  escalating via su

# Set SUID bit on the binary and restart
[web-prod-01]> escalate setuid
  Set SUID bit and restart? [y/N] y
  setuid set, restarting

# Run a custom escalation script on the client
[web-prod-01]> escalate script /opt/escalate.sh
```

After escalation, the client reconnects with the same HWID under the new privilege level. Just `use` the same ID/alias again.

### Systemd Service Management

```bash
# List services (with optional filter)
[web-prod-01]> service list nginx
  SERVICE                      ACTIVE   SUB       DESCRIPTION
  nginx.service                active   running   A high performance web server

# Service lifecycle
[web-prod-01]> service status nginx.service
[web-prod-01]> service restart nginx.service
  Restart nginx.service on web-prod? [y/N] y
  restart nginx.service: ok

[web-prod-01]> service enable nginx.service
[web-prod-01]> service disable nginx.service

# Install glob-client as a systemd service
[web-prod-01]> service install --name glob-vm --user root
  installed /etc/systemd/system/glob-vm.service

  Unit file:
    [Unit]
    Description=红猫 Daemon
    After=network-online.target
    ...

  next steps:
    systemctl enable glob-vm
    systemctl start glob-vm

# See all install options
[web-prod-01]> service install -h
```

### Full Deployment Workflow

```bash
# 1. Escalate to root
[web-prod-01]> escalate sudo
  Password: ********
  # Client reconnects as root

# 2. Move binary to system path
glob> use web01
[web-prod-01]> migrate /usr/local/bin/glob-vm
  # Client reconnects from new path

# 3. Install as systemd service
glob> use web01
[web-prod-01]> service install
[web-prod-01]> service enable glob-vm
[web-prod-01]> service start glob-vm
  # Daemon now survives reboots
```

---

## Network & Tunnels

### Network Information

```bash
# Network interfaces
[web-prod-01]> ifconfig
  eth0   UP  mtu 1500  00:1a:2b:3c:4d:5e
         inet 192.168.1.10/24
         inet6 fe80::1a2b:3cff:fe4d:5e6f/64
         RX: 1.2 GB (850K pkts)  TX: 450 MB (620K pkts)

  lo     UP  mtu 65536  00:00:00:00:00:00
         inet 127.0.0.1/8

# Socket connections
[web-prod-01]> netstat
  PROTO  LOCAL ADDRESS          PEER ADDRESS           STATE         PROCESS
  tcp    0.0.0.0:80             0.0.0.0:*              LISTEN        nginx/1234
  tcp    0.0.0.0:443            0.0.0.0:*              LISTEN        nginx/1234
  tcp    0.0.0.0:22             0.0.0.0:*              LISTEN        sshd/456

# Modes: listening (default), established, all, udp
[web-prod-01]> netstat established
[web-prod-01]> netstat all
[web-prod-01]> netstat udp
```

### Port Forwarding

SSH-style tunnel forwarding through the encrypted Diffie channel.

#### Local Forwarding (-L)

The **server** listens on a local port and forwards connections to a host:port reachable by the **client**.

```bash
# Access the client's local MySQL through server port 3307
[web-prod-01]> forward -L 3307:127.0.0.1:3306
  tunnel #1: server:3307 -> 127.0.0.1:3306 via a1b2c3d4

# Now connect locally on the server machine:
# mysql -h 127.0.0.1 -P 3307

# Access an internal service only reachable from the client's network
[web-prod-01]> forward -L 8080:internal-api.corp:443
  tunnel #2: server:8080 -> internal-api.corp:443 via a1b2c3d4
```

#### Remote Forwarding (-R)

The **client** listens on a port and forwards connections to a host:port reachable by the **server**.

```bash
# Expose server's local web app on the client's port 9090
[web-prod-01]> forward -R 9090:127.0.0.1:8080
  tunnel #3: client:9090 -> 127.0.0.1:8080 via a1b2c3d4

# Anyone connecting to web-prod-01:9090 reaches server's localhost:8080
```

#### Managing Tunnels

```bash
[web-prod-01]> tunnels
  #    TYPE LISTEN                   TARGET                   CLIENT     CONNS
  ----------------------------------------------------------------------------------
    1  -L   server:3307              127.0.0.1:3306           a1b2c3d4e5 2
    2  -L   server:8080              internal-api.corp:443    a1b2c3d4e5 0
    3  -R   client:9090              127.0.0.1:8080           a1b2c3d4e5 1

[web-prod-01]> tunnel close 2
  closed tunnel #2
```

### Route Management

Wrapper around `ip route` with safety guardrails to prevent accidentally killing the client's connection.

```bash
# View routing table
[web-prod-01]> route
  default via 192.168.1.1 dev eth0 proto dhcp metric 100
  10.0.0.0/8 via 10.0.0.1 dev eth1
  192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10

# Add a static route
[web-prod-01]> route add 172.16.0.0/12 via 10.0.0.1 dev eth1
  route added

# Delete a route
[web-prod-01]> route del 172.16.0.0/12
  route deleted

# Replace default gateway (triggers warning)
[web-prod-01]> route replace default via 10.0.0.1
  [!] WARNING: Replacing the default route may disconnect this client!
  Proceed? [y/N]
```

**Guardrails:**
- Warns before any modification to the **default route**
- Warns if a route appears to carry the **client's connection** back to the server (matches the client's source IP)
- All destructive route operations require explicit confirmation

```bash
# Full help
[web-prod-01]> route -h
```

---

## Monitoring & Observability

### Watch Mode

Repeatedly run a command at an interval — like the `watch` utility over the encrypted channel.

```bash
# Default: every 2 seconds
[web-prod-01]> watch ps nginx

# Custom interval
[web-prod-01]> watch -n 5 df -h /

# Ctrl+C to stop
```

### Session Monitoring

Monitor and interact with logged-in users on the client machine.

```bash
# List active sessions
[web-prod-01]> sessions
  USER     TTY      DATE        TIME   IDLE  PID
  oak      pts/0    2024-10-28  10:00  .     1234
  admin    pts/1    2024-10-28  09:45  1:30  5678

# Write a message to a user's terminal
[web-prod-01]> sessions write pts/0 System maintenance in 10 minutes

# Kill all processes on a terminal
[web-prod-01]> sessions kill pts/1

# Spy on terminal output in real-time (via strace)
[web-prod-01]> sessions listen pts/0
  [streaming terminal output...]
  # Ctrl+C to stop

[web-prod-01]> sessions stop
```

### Journal / Syslog

Query systemd journal with familiar options.

```bash
# Recent entries
[web-prod-01]> journal

# Filter by unit
[web-prod-01]> journal -u nginx

# Filter by time
[web-prod-01]> journal --since "1 hour ago"

# Filter by priority
[web-prod-01]> journal -p err

# Grep for patterns
[web-prod-01]> journal -g "connection refused"

# Limit lines
[web-prod-01]> journal -n 50

# Previous boot
[web-prod-01]> journal -b -1

# Combine filters
[web-prod-01]> journal -u sshd -p warning --since "2024-10-28"

# Full help
[web-prod-01]> journal -h
```

### File Search

```bash
# Search by name
[web-prod-01]> find /etc -name "*.conf"

# Search by type (f=file, d=directory, l=symlink)
[web-prod-01]> find /var/log -type f -name "*.log"

# Search by size and age
[web-prod-01]> find /tmp -size +100M -mtime +7

# Limit depth
[web-prod-01]> find / -maxdepth 3 -name "passwd"

# Across a group
[@production (3)]> find /var/log -name "error*" -type f
```

### Login/Logout Monitoring

The client automatically monitors user logins and logouts (polling `who` every 30 seconds) and sends real-time events to the server:

```
[+user] oak logged in on web-prod-01 (pts/0)
[-user] admin logged out from web-prod-01 (pts/1)
```

These appear as colored notifications in the server shell regardless of what you're doing.

### Latency Monitoring

Latency is computed automatically from the keepalive ping-pong cycle (every 25 seconds). The `who` display color-codes it:

- **Green** (<50ms): healthy
- **Yellow** (50-150ms): elevated
- **Red** (>150ms): high latency or degraded connection

---

## Package Management

Auto-detects the client's package manager (dnf, apt-get, pacman, zypper) and provides a unified interface. All commands use safe argument arrays — no shell injection possible.

```bash
# List installed packages
[web-prod-01]> pkg list

# Search for a package
[web-prod-01]> pkg search nginx

# Install (requires confirmation)
[web-prod-01]> pkg install htop
  Install htop? [y/N] y

# Remove (requires confirmation)
[web-prod-01]> pkg remove htop
  Remove htop? [y/N] y

# Update package index
[web-prod-01]> pkg update

# Upgrade all packages (requires confirmation)
[web-prod-01]> pkg upgrade
  Upgrade all packages? [y/N] y

# Package details
[web-prod-01]> pkg info nginx
```

Works across groups — `[@production]> pkg list` queries all members in parallel.

---

## Scripting & Automation

### Script Macros

Record a sequence of commands and replay them later. Scripts are persisted to `glob_data.json` and survive server restarts. Scripts can include context switches (`use`/`back`), so a single macro can orchestrate actions across multiple clients.

```bash
# Start recording
glob> script record deploy-web

[REC:deploy-web] glob> use web01
[REC:deploy-web] [web-prod-01]> exec systemctl stop nginx
[REC:deploy-web] [web-prod-01]> upload ./nginx.conf /etc/nginx/nginx.conf
[REC:deploy-web] [web-prod-01]> exec systemctl start nginx
[REC:deploy-web] [web-prod-01]> exec systemctl status nginx
[REC:deploy-web] [web-prod-01]> back

# Stop recording
[REC:deploy-web] glob> script stop
  saved script 'deploy-web' (5 commands)

# Replay
glob> script run deploy-web

# View contents
glob> script show deploy-web
  1: use web01
  2: exec systemctl stop nginx
  3: upload ./nginx.conf /etc/nginx/nginx.conf
  4: exec systemctl start nginx
  5: exec systemctl status nginx

# List all scripts
glob> script list

# Delete
glob> script delete deploy-web
```

### Client-to-Client Transfer (scp)

Copy files between two connected clients without downloading to the server first (internally uses a temp file intermediary).

```bash
glob> scp web01:/etc/nginx/nginx.conf db01:/tmp/nginx.conf.bak
  downloading from web01...
  uploading to db01...
  transferred 2.4 KB
```

### Command History

```bash
glob> history
  2024-10-28 10:00:15  [web01]  exec uptime
  2024-10-28 10:01:23  [web01]  ps nginx
  2024-10-28 10:02:45  [global] who
  ...

# Last N entries
glob> history 20
```

---

## Daemon Lifecycle

### Restart

Re-exec the daemon binary. The process replaces itself (`Process.exec`), maintaining the same PID namespace but resetting all state. The client reconnects with the same HWID.

```bash
[web-prod-01]> restart
```

### Migrate

Copy the binary to a new path and re-exec from there. Useful for moving to a system directory before installing as a service.

```bash
[web-prod-01]> migrate /usr/local/bin/glob-vm
  migrated, restarting from /usr/local/bin/glob-vm
```

### Daemonize

Detach from the terminal using `setsid` — the process becomes a proper background daemon with its own session.

```bash
[web-prod-01]> daemonize
  daemonized (pid 12345, log: /tmp/.red-cat.log)

# With custom paths
[web-prod-01]> daemonize --log /var/log/glob.log --pidfile /var/run/glob.pid
```

### Kill Daemon

Immediately terminate the client process with no restart.

```bash
[web-prod-01]> kill-daemon
```

### Signal Handling

The client traps `SIGINT` and `SIGTERM` for clean shutdown — it sets a flag that breaks the reconnect loop, allowing in-flight operations to complete.

---

## Deployment

### Recommended Deployment Workflow

```bash
# 1. Build a portable static binary
./build-static.sh glob-client

# 2. Transfer to target machine
scp glob-client user@target:/tmp/

# 3. On target: start the client
ssh user@target '/tmp/glob-client &'

# 4. On server: client appears in the listing
glob> who

# 5. Escalate to root
glob> use <client>
[target]> escalate sudo
  Password: ********

# 6. Move to system path
glob> use <client>
[target]> migrate /usr/local/bin/glob-vm

# 7. Install as a persistent service
glob> use <client>
[target]> service install --name glob-vm
[target]> service enable glob-vm
[target]> service start glob-vm
```

After step 7, the daemon starts automatically on boot, restarts on crash (systemd `Restart=always`), and logs to journald.

---

## Building from Source

### Requirements

- **Server**: Ruby 3.x with OpenSSL
- **Client**: Crystal 1.x

### Development Build

```bash
crystal build client.cr -o glob-client
```

### Static Build (Portable)

Uses Docker with Alpine/musl for a fully static, zero-dependency binary.

```bash
./build-static.sh glob-client
```

The build script:
1. Builds a Docker image with Crystal + static libraries (OpenSSL, zlib, yaml, gc)
2. Compiles with `-Oz --single-module --static --no-debug`
3. Links with `--gc-sections --build-id=none` to strip unused code
4. Runs `strip --strip-all` for minimum size
5. Handles SELinux (`:z` volume flag) and file ownership (`chown`)

Output: ~7.6MB fully static PIE binary that runs on any Linux x86_64 system.

### Running Tests

```bash
# Crystal client tests (52 specs)
crystal spec

# Ruby server tests
ruby -Isrc -Itest test/shell_test.rb    # 37 tests
ruby -Isrc -Itest test/storage_test.rb  # 23 tests
```

---

## Command Reference

### Global Commands (no client selected)

| Command | Description |
|---------|-------------|
| `use <id\|alias\|@group>` | Select a client or group |
| `who` / `list` | Show all connected clients with details |
| `broadcast <message>` | Send message to all clients |
| `kick <id>` | Disconnect a client |
| `group create\|delete\|add\|remove\|list` | Manage groups |
| `alias set\|remove\|list` | Manage aliases |
| `note set\|remove` | Manage client notes |
| `history [N]` | Show command history |
| `script record\|stop\|run\|show\|list\|delete` | Macro management |
| `scp <src>:<path> <dst>:<path>` | Client-to-client transfer |
| `help` | Show help |
| `quit` | Exit |

### Client Commands (client or group selected)

| Category | Command | Description |
|----------|---------|-------------|
| **Filesystem** | `cd`, `pwd`, `ls`, `cat`, `edit` | Navigate and view files |
| | `download`, `upload` | SHA256-verified file transfer |
| **Exec** | `exec <cmd>` | Run shell command |
| | `shell` | Interactive bash session |
| **Memfile** | `memfile edit\|upload\|exec\|cat\|list\|delete` | In-memory scripts |
| **Cron** | `cron list\|add\|remove` | Crontab management |
| **Sysadmin** | `ps [filter]`, `top` | Process info |
| | `reboot`, `shutdown` | Power management |
| | `restart`, `migrate`, `daemonize`, `kill-daemon` | Daemon lifecycle |
| | `escalate sudo\|su\|setuid\|script` | Privilege escalation |
| **Services** | `service list\|status\|start\|stop\|restart\|enable\|disable\|install` | Systemd management |
| **Network** | `ifconfig` / `ip`, `netstat` | Network info |
| | `forward -L\|-R`, `tunnels`, `tunnel close` | Port forwarding |
| | `route show\|add\|del\|replace` | Routing with guardrails |
| **Monitor** | `watch [-n sec] <cmd>` | Periodic command execution |
| | `sessions list\|kill\|write\|listen\|stop` | User session management |
| | `journal [options]` | Systemd journal query |
| | `find [path] [options]` | Remote file search |
| **Packages** | `pkg list\|search\|install\|remove\|update\|upgrade\|info` | Package management |
| **Meta** | `info` | Full client sysinfo |
| | `who` | Show all clients |
| | `back` | Deselect client |

### Tab Completion

The server shell supports tab completion for:
- **Commands**: Context-aware (global commands vs. client commands)
- **Client IDs**: HWIDs, hostnames, aliases, and group names when typing `use`
- **History**: Arrow keys (up/down), Ctrl+R for reverse search

### Output Paging

Commands producing more than 30 lines of output are automatically piped through `less -R` (with color support) when running on a TTY.
