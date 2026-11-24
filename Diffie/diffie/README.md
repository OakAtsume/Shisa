# diffie (Crystal client)

A Crystal client for the **Diffie** encrypted-messaging protocol. Speaks the same
wire format as the Ruby reference in `../server/` (`main.rb` server, `client.rb`
client).

## Protocol

1. **Handshake** — MODP Diffie-Hellman (generator `2`). Each side sends its
   public key as a 256-byte, left-zero-padded big-endian integer. The shared
   secret is run through **HKDF-SHA256** (`info = "diffie/v1"`) to derive *two*
   32-byte keys: `c2s` for client→server traffic and `s2c` for server→client.
   Separate keys per direction mean the two nonce counters live in different
   keyspaces and can never collide.
2. **Records** — every message is framed as:

   ```
   ┌──────────┬───────────┬───────────────┬───────────┐
   │ 4 bytes  │ 12 bytes  │ N bytes       │ 16 bytes  │
   │ length   │ nonce     │ ciphertext    │ Poly1305  │
   │ (BE u32) │           │ (ChaCha20)    │ tag       │
   └──────────┴───────────┴───────────────┴───────────┘
   ```

   `length` covers everything after itself (nonce + ciphertext + tag). The
   cipher is IETF **ChaCha20-Poly1305** with no AAD.
3. **Nonce / replay** — the nonce is 4 zero bytes followed by an 8-byte
   big-endian counter, starting at 1 and incrementing per message. A receiver
   rejects any nonce that does not strictly increase.

## Build & run

```sh
shards install            # fetches the rfc8439 shard (already vendored in lib/)
crystal run src/diffie.cr -- [host] [port]   # defaults to 127.0.0.1 8081
```

Type a line and press enter to send; `exit` (or Ctrl-D) quits.

Build a standalone binary:

```sh
crystal build src/diffie.cr -o diffie --release
./diffie 127.0.0.1 8081
```

## Layout

| File             | Purpose                                                              |
| ---------------- | ------------------------------------------------------------------- |
| `src/aead.cr`    | ChaCha20-Poly1305 `seal`/`open`, byte-compatible with OpenSSL.       |
| `src/hkdf.cr`    | HKDF-SHA256 (RFC 5869), matches Ruby's `OpenSSL::KDF.hkdf`.          |
| `src/session.cr` | `Diffie::Session` — transport-agnostic protocol + framing helpers.   |
| `src/client.cr`  | `SecureClient`: the TCP binding built on `Diffie::Session`.          |
| `src/diffie.cr`  | Entry point — interactive encrypted REPL.                            |

## Embedding (TCP)

```crystal
require "./src/client"

client = SecureClient.new("127.0.0.1", 8081)
client.on_message { |id, msg| puts "#{id}: #{msg}" }
client.on_protocol_error { |id, err, msg| STDERR.puts "#{err}: #{msg}" }
client.connect
client.send("hello")
```

## Manual / transport-agnostic use (no sockets)

`Diffie::Session` is the protocol with the transport ripped out — you feed it
bytes and it gives you bytes, so you can carry them over **anything**: SMS, an
HTTP header, a websocket, a QR code, a file. `SecureClient` above is just a thin
TCP wrapper around it.

The flow is three steps:

```crystal
require "./src/session"

# One side is the Client, the other the Server (this only picks which
# directional key each uses — the DH math is identical either way).
alice = Diffie::Session.new(Diffie::Role::Client)
bob   = Diffie::Session.new(Diffie::Role::Server)

# 1. Exchange public keys (256 bytes each) over any channel you like.
alice.complete_handshake(bob.local_public_key)
bob.complete_handshake(alice.local_public_key)

# 2. Encrypt → a self-contained record (nonce ‖ ciphertext ‖ tag), no length
#    prefix, so it fits a single message/datagram.
record = alice.encrypt("meet at noon")        # => Bytes

# 3. Decrypt records you receive. Verifies the tag and rejects replays.
puts String.new(bob.decrypt(record))          # => "meet at noon"
```

### Over a text channel (SMS, headers)

Channels that only carry text can't hold raw bytes — use the Base64 helpers,
which produce ASCII-safe strings:

```crystal
sms = alice.encrypt_to_base64("meet at noon")  # => "AAAAAAAA…" (paste into an SMS)
bob.decrypt_from_base64(sms)                    # => Bytes -> "meet at noon"
```

See [`examples/manual.cr`](examples/manual.cr) for a runnable end-to-end demo
(`crystal run examples/manual.cr`).

### Over a byte stream (TCP, pipes)

A record has no built-in boundary, so on a stream prepend a length header with
`Diffie::Framing` and reassemble with `Diffie::FrameParser`:

```crystal
socket.write(Diffie::Framing.frame(alice.encrypt("hello")))   # sender

parser = Diffie::FrameParser.new                              # receiver
parser.feed(chunk) { |record| handle(bob.decrypt(record)) }
```

### Errors

`decrypt` raises `Diffie::ReplayError` (nonce didn't increase) or
`Diffie::DecryptError` (bad tag / corrupt / too short); `complete_handshake`
raises `Diffie::HandshakeError` (wrong size or degenerate public key). All
inherit `Diffie::Error`.

> **Note on reordering transports.** Replay protection requires nonces to
> *strictly increase*, which assumes in-order delivery (true for TCP). If your
> channel can reorder or duplicate messages (some SMS gateways), a legitimately
> out-of-order record will raise `ReplayError`. For those, you'd want a
> sliding-window replay check instead — ask if you want one added.

## Tests

```sh
crystal spec
```

The spec freezes a known OpenSSL `chacha20-poly1305` vector to guarantee the
client stays wire-compatible with the reference server.
