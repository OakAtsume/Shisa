require "big"
require "base64"
require "./aead"
require "./hkdf"

# Transport-agnostic implementation of the Diffie protocol.
#
# `Diffie::Session` knows nothing about sockets. You drive it by hand:
#
#   1. exchange public keys (256 bytes each), however you like;
#   2. call `encrypt` to turn a message into a self-contained record;
#   3. hand that record to your peer over *any* channel;
#   4. call `decrypt` on records you receive.
#
# Because a record carries its own nonce + tag and has no length prefix, it
# suits message/datagram transports (SMS, a single HTTP header, a QR code) just
# as well as a byte stream. For stream transports, wrap each record with
# `Diffie::Framing` so the receiver can find record boundaries.
module Diffie
  # MODP Diffie-Hellman group + protocol constants. Both peers MUST agree on
  # these. NOTE: this prime is the (broken) value from the reference server —
  # replace it with RFC 3526 Group 14 or move to X25519 for real use.
  PRIME = BigInt.new(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" \
    "020BBEA63B139B22514A08798E3404DD29024E088A67CC74020BBEA63B139B22" \
    "514A08798E3404DDE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
  GENERATOR    = BigInt.new(2)
  PUBKEY_BYTES = 256
  HKDF_INFO    = "diffie/v1"
  NONCE_LEN    = 12
  TAG_LEN      = 16

  # Which half of the HKDF output this side encrypts with. Both peers run the
  # same DH + HKDF; the role only decides who uses the c2s key vs the s2c key.
  enum Role
    Client
    Server
  end

  class Error < Exception; end

  class HandshakeError < Error; end

  # Raised by `decrypt` when a record's nonce did not strictly increase
  # (replay, or out-of-order delivery on a reordering transport).
  class ReplayError < Error; end

  # Raised by `decrypt` when authentication fails (tampering / wrong key).
  class DecryptError < Error; end

  class Session
    getter role : Role
    getter? handshake_complete : Bool

    def initialize(@role : Role)
      @priv = BigInt.new(Random::Secure.hex(32), 16)
      @public_key = nil.as(Bytes?)
      @send_key = Bytes.new(32)
      @recv_key = Bytes.new(32)
      @send_nonce = 1_u64 # first transmitted nonce; receivers require > 0
      @highest_seen = BigInt.new(0)
      @handshake_complete = false
    end

    # --- handshake -----------------------------------------------------------

    # Our DH public key as 256 raw big-endian bytes. Send this to your peer.
    # Stable across calls for the life of the session.
    def local_public_key : Bytes
      @public_key ||= to_padded_bytes(powmod(GENERATOR, @priv, PRIME), PUBKEY_BYTES)
    end

    # Feed your peer's 256-byte public key to derive the directional keys.
    def complete_handshake(peer_public_key : Bytes) : Nil
      unless peer_public_key.size == PUBKEY_BYTES
        raise HandshakeError.new("peer public key must be #{PUBKEY_BYTES} bytes, got #{peer_public_key.size}")
      end

      peer = BigInt.new(peer_public_key.hexstring, 16)
      # Reject degenerate keys (0, 1, p-1) that would force a known secret.
      unless peer > 1 && peer < PRIME - 1
        raise HandshakeError.new("peer public key is out of range")
      end

      secret = powmod(peer, @priv, PRIME)
      okm = HKDF.derive(secret_to_bytes(secret), "", HKDF_INFO, 64)
      c2s = okm[0, 32]  # client -> server
      s2c = okm[32, 32] # server -> client

      case @role
      in Role::Client then @send_key, @recv_key = c2s, s2c
      in Role::Server then @send_key, @recv_key = s2c, c2s
      end
      @handshake_complete = true
    end

    # --- messaging -----------------------------------------------------------

    # Encrypt one message into a self-contained record: nonce ‖ ciphertext ‖ tag.
    # Advances the send-nonce. Safe to ship over any transport as-is.
    def encrypt(plaintext : Bytes) : Bytes
      ensure_ready
      nonce = next_nonce
      ciphertext, tag = AEAD.seal(@send_key, nonce, plaintext)

      record = Bytes.new(nonce.size + ciphertext.size + tag.size)
      nonce.copy_to(record[0, nonce.size])
      ciphertext.copy_to(record[nonce.size, ciphertext.size])
      tag.copy_to(record[nonce.size + ciphertext.size, tag.size])
      record
    end

    def encrypt(plaintext : String) : Bytes
      encrypt(plaintext.to_slice)
    end

    # Decrypt a record produced by the peer's `encrypt`. Verifies the tag and
    # enforces strictly-increasing nonces. Raises `ReplayError` / `DecryptError`
    # on failure.
    def decrypt(record : Bytes) : Bytes
      ensure_ready
      if record.size < NONCE_LEN + TAG_LEN
        raise DecryptError.new("record too short (#{record.size} bytes)")
      end

      nonce = record[0, NONCE_LEN]
      body = record[NONCE_LEN, record.size - NONCE_LEN]
      ciphertext = body[0, body.size - TAG_LEN]
      tag = body[body.size - TAG_LEN, TAG_LEN]

      numeric = BigInt.new(nonce.hexstring, 16)
      raise ReplayError.new("nonce did not increase (#{numeric} <= #{@highest_seen})") if numeric <= @highest_seen

      plaintext = AEAD.open(@recv_key, nonce, ciphertext, tag)
      raise DecryptError.new("authentication failed") if plaintext.nil?

      # Advance the replay marker only after a record authenticates, so a forged
      # high-nonce packet can't bump it and lock out legitimate traffic.
      @highest_seen = numeric
      plaintext
    end

    # --- text-transport convenience -----------------------------------------
    # SMS and headers carry text, not raw bytes — Base64 a record for those.

    def encrypt_to_base64(plaintext) : String
      Base64.strict_encode(encrypt(plaintext))
    end

    def decrypt_from_base64(text : String) : Bytes
      decrypt(Base64.decode(text))
    end

    # --- helpers -------------------------------------------------------------

    private def ensure_ready
      raise HandshakeError.new("handshake not complete") unless @handshake_complete
    end

    # 12-byte nonce: 4 zero bytes + 8-byte big-endian counter.
    private def next_nonce : Bytes
      n = @send_nonce
      @send_nonce += 1
      nonce = Bytes.new(NONCE_LEN, 0_u8)
      IO::ByteFormat::BigEndian.encode(n, nonce[4, 8])
      nonce
    end

    private def powmod(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
      result = BigInt.new(1)
      base %= mod
      while exp > 0
        result = (result * base) % mod if exp.odd?
        exp >>= 1
        base = (base * base) % mod
      end
      result
    end

    private def to_padded_bytes(n : BigInt, width : Int32) : Bytes
      raw = hex_to_bytes(n)
      padded = Bytes.new(width, 0_u8)
      raw.copy_to(padded[width - raw.size, raw.size])
      padded
    end

    private def secret_to_bytes(n : BigInt) : Bytes
      hex_to_bytes(n)
    end

    private def hex_to_bytes(n : BigInt) : Bytes
      hex = n.to_s(16)
      hex = "0#{hex}" if hex.size.odd?
      hex.hexbytes
    end
  end

  # Length-prefix framing for *stream* transports (TCP, pipes). A record has no
  # built-in boundary, so on a byte stream you prepend its length.
  module Framing
    extend self

    HEADER_SIZE = 4
    MAX_FRAME   = 500_000_000

    # Prepend a 4-byte big-endian length to a record.
    def frame(record : Bytes) : Bytes
      framed = Bytes.new(HEADER_SIZE + record.size)
      IO::ByteFormat::BigEndian.encode(record.size.to_u32, framed[0, HEADER_SIZE])
      record.copy_to(framed[HEADER_SIZE, record.size])
      framed
    end
  end

  # Accumulates stream bytes and yields complete records as they arrive.
  #
  #   parser = Diffie::FrameParser.new
  #   parser.feed(chunk) { |record| session.decrypt(record) }
  #
  # Raises `Error` if a length header is zero or absurdly large.
  class FrameParser
    def initialize
      @buffer = IO::Memory.new
    end

    def feed(chunk : Bytes, & : Bytes ->) : Nil
      @buffer.write(chunk)
      bytes = @buffer.to_slice
      offset = 0

      while bytes.size - offset >= Framing::HEADER_SIZE
        length = IO::ByteFormat::BigEndian.decode(UInt32, bytes[offset, Framing::HEADER_SIZE])
        if length == 0 || length > Framing::MAX_FRAME
          raise Error.new("frame length out of range (#{length})")
        end
        break if bytes.size - offset < Framing::HEADER_SIZE + length

        record = bytes[offset + Framing::HEADER_SIZE, length]
        offset += Framing::HEADER_SIZE + length
        yield record
      end

      # Keep only the unconsumed tail.
      rest = bytes[offset, bytes.size - offset]
      @buffer.clear
      @buffer.write(rest)
    end
  end
end
