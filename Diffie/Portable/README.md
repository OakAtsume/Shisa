# Portable (Ruby)

A transport-agnostic Ruby implementation of the Diffie protocol — the Ruby
analogue of the Crystal `Diffie::Session`. It knows nothing about sockets: you
feed it bytes and it gives you bytes, so you can carry them over **anything** —
TCP, SMS, an HTTP header, a QR code, a file.

Wire-compatible with the reference server in `../server` and with the Crystal
client (both go through OpenSSL's `chacha20-poly1305` + `OpenSSL::KDF.hkdf`).

> This folder is a standalone copy; it does **not** touch `../server`.

## Protocol

1. **Handshake** — MODP Diffie-Hellman (generator `2`). Each side sends its
   public key as a 256-byte, left-zero-padded big-endian integer. The shared
   secret is run through HKDF-SHA256 (`info = "diffie/v1"`) into two 32-byte
   keys: `c2s` (client→server) and `s2c` (server→client). Separate keys per
   direction mean the two nonce counters can never collide.
2. **Record** — `12-byte nonce ‖ ciphertext ‖ 16-byte Poly1305 tag`. Self
   contained, no length prefix, so it fits a single message/datagram.
3. **Nonce / replay** — 4 zero bytes + 8-byte big-endian counter, starting at 1
   and incrementing. A receiver rejects any nonce that doesn't strictly
   increase.

## Files

| File                    | Purpose                                              |
| ----------------------- | ---------------------------------------------------- |
| `diffie.rb`             | The library: `Diffie::Session`, `Framing`, `FrameParser`. |
| `example_manual.rb`     | No-socket SMS-style demo (`ruby example_manual.rb`). |
| `example_tcp_client.rb` | TCP client built on `Session`, talks to `../server`. |

## Manual / transport-agnostic use

```ruby
require_relative "diffie"

# One side is :client, the other :server (this only picks which directional key
# each uses — the DH math is identical either way).
alice = Diffie::Session.new(:client)
bob   = Diffie::Session.new(:server)

# 1. Exchange public keys (256 bytes each) over any channel.
alice.complete_handshake(bob.local_public_key)
bob.complete_handshake(alice.local_public_key)

# 2. Encrypt -> a self-contained record (binary String).
record = alice.encrypt("meet at noon")

# 3. Decrypt records you receive (verifies the tag, rejects replays).
puts bob.decrypt(record)            # => "meet at noon"
```

### Over a text channel (SMS, headers)

Text channels can't carry raw bytes — use the Base64 helpers:

```ruby
sms = alice.encrypt_to_base64("meet at noon")   # ASCII-safe, paste into an SMS
bob.decrypt_from_base64(sms)                     # => "meet at noon"
```

### Over a byte stream (TCP, pipes)

A record has no built-in boundary, so on a stream prepend a length header with
`Diffie::Framing` and reassemble with `Diffie::FrameParser`:

```ruby
socket.write(Diffie::Framing.frame(alice.encrypt("hello")))   # sender

parser = Diffie::FrameParser.new                              # receiver
parser.feed(chunk) { |record| handle(bob.decrypt(record)) }
```

## Errors

`decrypt` raises `Diffie::ReplayError` (nonce didn't increase) or
`Diffie::DecryptError` (bad tag / corrupt / too short); `complete_handshake`
raises `Diffie::HandshakeError` (wrong size or degenerate public key). All
inherit `Diffie::Error`.

> **Reordering transports.** Replay protection requires strictly-increasing
> nonces, which assumes in-order delivery (true for TCP). If your channel can
> reorder or duplicate messages (some SMS gateways), a legitimately out-of-order
> record raises `ReplayError`; you'd want a sliding-window replay check instead.

## Try it

```sh
ruby example_manual.rb                       # no sockets, SMS-style
ruby example_tcp_client.rb 127.0.0.1 8081    # against ../server/main.rb
```
