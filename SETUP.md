# GLOB-VM Fleet Control — Setup Guide

## Prerequisites

- **Server**: Ruby 3.x with OpenSSL (ships with stdlib)
- **Client**: Crystal 1.x with OpenSSL development headers (`libssl-dev` / `openssl-devel`)

## 1. Generate Keys

All keys are Ed25519 keypairs stored as hex-encoded 32-byte files.

### Generate both server and client keys at once

```bash
ruby keys/generate.rb
```

This creates:
- `keys/server.key` — server private key (chmod 0600)
- `keys/server.pub` — server public key
- `keys/client.key` — client private key (chmod 0600)
- `keys/client.pub` — client public key
- `keys/authorized_clients/<prefix>.pub` — client auto-registered for server auth

### Generate a client key only

```bash
ruby keys/generate.rb client
```

The client's public key is automatically added to `keys/authorized_clients/`.

### Generate a server key only

```bash
ruby keys/generate.rb server
```

## 2. Server Setup

1. Generate a server keypair (see above).
2. The server loads its identity from `keys/server.key` on startup.
3. Authorized client public keys are loaded from `keys/authorized_clients/*.pub`.
4. Start the server:

```bash
ruby server.rb [port]
# Default port: 32435
```

The server will print its identity fingerprint and the number of authorized clients on startup.

### Adding more clients later

Either run `ruby keys/generate.rb client` again, or manually:

1. Generate a keypair on any machine: `ruby keys/generate.rb client`
2. Copy the `.pub` file into `keys/authorized_clients/` on the server
3. Restart the server (or it picks up new keys on next connection)

## 3. Client Setup

Each client binary has a unique Ed25519 identity compiled in. This proves the binary was issued by you, and the server will only accept connections from clients whose public keys are registered.

### Build with the builder script (recommended)

The builder automates keypair generation, source patching, compilation, and optional UPX compression:

```bash
ruby tools/build_client.rb \
  --host 10.0.0.1:32435 \
  --server-key $(cat keys/server.pub) \
  --register \
  --static --upx \
  --output glob-client
```

Multi-server failover (client tries each in order):

```bash
ruby tools/build_client.rb \
  --host primary.example.com:32435 \
  --host primary.example.com:443 \
  --host backup.example.com:22 \
  --server-key $(cat keys/server.pub) \
  --register --static --upx
```

Options:

| Flag | Description |
|------|-------------|
| `--host HOST[:PORT]` | Control server (repeatable for failover) |
| `--port PORT` | Default port when host has none (default: 32435) |
| `--server-key HEX` | Server public key (auto-reads `keys/server.pub`) |
| `--output NAME` | Binary name (default: `glob-client`) |
| `--static` | Static build via Docker alpine |
| `--upx` | Compress with UPX after build |
| `--register` | Auto-register client key in `keys/authorized_clients/` |
| `--respect-tries BOOL` | Retry each host N times before failover (default: true) |
| `--dry-run` | Show plan without building |

### Build manually

1. Generate a client keypair:
   ```bash
   ruby keys/generate.rb client
   ```

2. Edit `client.cr` — set `TRUSTED_SERVER_KEYS`, `CLIENT_PRIVATE_KEY`, and `SERVERS`.

3. Build:
   ```bash
   crystal build client.cr -o glob-client --release --static
   ```

### Multi-server failover

The client `SERVERS` list defines control servers tried in order. If `RESPECT_TRIES` is true (default), each server gets `MAX_RETRIES` (3) attempts before moving to the next. After all servers are exhausted, the client backs off for `BACKOFF_DELAY` (5 minutes) before restarting the cycle.

This handles restricted networks (try port 443, then 22) and primary/backup redundancy.

### Registering new clients on a running server

After building a new client with `--register`, tell the running server to pick it up without restarting:

```
glob> refresh
reloaded 3 authorized client keys from keys/authorized_clients/
```

## 4. Data Storage

The server stores data in two directories:

### `db/` — Configuration data

| File | Contents |
|------|----------|
| `db/groups.json` | Client groups |
| `db/aliases.json` | Client aliases (friendly names) |
| `db/notes.json` | Per-client notes (keyed by HWID) |
| `db/scripts.json` | Command macros |

### `logs/` — Daily log files

Command history and events are stored as `logs/dd-mm-yyyy.json` files, one per day.

### Migration from `glob_data.json`

If a legacy `glob_data.json` exists when the server starts, it is automatically migrated to the new `db/` and `logs/` layout. The original file is renamed to `glob_data.json.bak`.

## 5. Crypto Protocol

The handshake uses:
- **X25519 ECDH** for key exchange (32-byte public keys)
- **HKDF-SHA256** for key derivation
- **ChaCha20-Poly1305** for symmetric encryption (AEAD)
- **Ed25519** for mutual authentication (inside the encrypted channel)

Wire flow:
```
Client → Server:  32B X25519 public key
Server → Client:  32B X25519 public key
  (both derive shared secret via HKDF)
Server → Client:  encrypted AUTH_CHALLENGE (1B type + 32B ed25519 pub + 64B sig)
Client → Server:  encrypted AUTH_RESPONSE  (1B type + 32B ed25519 pub + 64B sig)
  (encrypted session established)
```

Ed25519 public keys are never exposed in plaintext — authentication happens inside the encrypted tunnel. The auth transcript binds to the X25519 session keys with role separation (server=0x01, client=0x02) to prevent reflection and replay attacks.
