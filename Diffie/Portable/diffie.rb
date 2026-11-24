# frozen_string_literal: true

require "openssl"
require "securerandom"
require "base64"

# Transport-agnostic implementation of the Diffie protocol (Ruby port of the
# Crystal `Diffie::Session`). It knows nothing about sockets: you feed it bytes
# and it gives you bytes, so you can carry them over anything — TCP, SMS, an
# HTTP header, a QR code, a file.
#
#   1. exchange public keys (256 bytes each), however you like;
#   2. call #encrypt to turn a message into a self-contained record;
#   3. hand that record to your peer over any channel;
#   4. call #decrypt on records you receive.
#
# Wire-compatible with the reference server in ../server and the Crystal client.
module Diffie
  # MODP Diffie-Hellman group + protocol constants. Both peers MUST agree on
  # these. NOTE: this prime is the (broken) value from the reference server —
  # replace it with RFC 3526 Group 14 or move to X25519 for real use.
  PRIME = OpenSSL::BN.new(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" \
    "020BBEA63B139B22514A08798E3404DD29024E088A67CC74020BBEA63B139B22" \
    "514A08798E3404DDE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
  )
  GENERATOR    = OpenSSL::BN.new(2)
  PUBKEY_BYTES = 256
  HKDF_INFO    = "diffie/v1"
  NONCE_LEN    = 12
  TAG_LEN      = 16

  # Roles: :client and :server. The role only decides which half of the HKDF
  # output this side encrypts with — the DH math is identical either way.
  ROLES = %i[client server].freeze

  class Error < StandardError; end
  class HandshakeError < Error; end
  # Raised by #decrypt when a record's nonce did not strictly increase
  # (replay, or out-of-order delivery on a reordering transport).
  class ReplayError < Error; end
  # Raised by #decrypt when authentication fails (tampering / wrong key).
  class DecryptError < Error; end

  class Session
    attr_reader :role

    def initialize(role)
      raise ArgumentError, "role must be :client or :server" unless ROLES.include?(role)

      @role = role
      @priv = OpenSSL::BN.rand(256)
      @public_key = nil
      @send_key = nil
      @recv_key = nil
      @send_nonce = 1 # first transmitted nonce; receivers require > 0
      @highest_seen = 0
      @handshake_complete = false
    end

    def handshake_complete?
      @handshake_complete
    end

    # --- handshake -----------------------------------------------------------

    # Our DH public key as 256 raw big-endian bytes (a binary String). Send this
    # to your peer. Stable across calls for the life of the session.
    def local_public_key
      @public_key ||= int_to_padded_bytes(GENERATOR.mod_exp(@priv, PRIME), PUBKEY_BYTES)
    end

    # Feed your peer's 256-byte public key to derive the directional keys.
    def complete_handshake(peer_public_key)
      peer_public_key = peer_public_key.b
      unless peer_public_key.bytesize == PUBKEY_BYTES
        raise HandshakeError, "peer public key must be #{PUBKEY_BYTES} bytes, got #{peer_public_key.bytesize}"
      end

      peer = OpenSSL::BN.new(peer_public_key, 2)
      # Reject degenerate keys (0, 1, p-1) that would force a known secret.
      unless peer > OpenSSL::BN.new(1) && peer < PRIME - OpenSSL::BN.new(1)
        raise HandshakeError, "peer public key is out of range"
      end

      secret = peer.mod_exp(@priv, PRIME)
      okm = OpenSSL::KDF.hkdf(int_to_min_bytes(secret), salt: "", info: HKDF_INFO, length: 64, hash: "SHA256")
      c2s = okm[0, 32] # client -> server
      s2c = okm[32, 32] # server -> client

      if @role == :client
        @send_key = c2s
        @recv_key = s2c
      else
        @send_key = s2c
        @recv_key = c2s
      end
      @handshake_complete = true
      nil
    end

    # --- messaging -----------------------------------------------------------

    # Encrypt one message into a self-contained record: nonce + ciphertext + tag
    # (a binary String). Advances the send-nonce. Ship it over any transport.
    def encrypt(plaintext)
      ensure_ready
      nonce = next_nonce

      cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
      cipher.key = @send_key
      cipher.iv = nonce
      ciphertext = cipher.update(plaintext.b) + cipher.final
      tag = cipher.auth_tag # 16 bytes

      (nonce + ciphertext + tag).b
    end

    # Decrypt a record produced by the peer's #encrypt. Verifies the tag and
    # enforces strictly-increasing nonces. Raises ReplayError / DecryptError.
    def decrypt(record)
      ensure_ready
      record = record.b
      raise DecryptError, "record too short (#{record.bytesize} bytes)" if record.bytesize < NONCE_LEN + TAG_LEN

      nonce      = record[0, NONCE_LEN]
      tag        = record[-TAG_LEN, TAG_LEN]
      ciphertext = record[NONCE_LEN...(record.bytesize - TAG_LEN)]

      numeric = nonce.unpack1("H*").to_i(16)
      raise ReplayError, "nonce did not increase (#{numeric} <= #{@highest_seen})" if numeric <= @highest_seen

      cipher = OpenSSL::Cipher.new("chacha20-poly1305").decrypt
      cipher.key = @recv_key
      cipher.iv = nonce
      cipher.auth_tag = tag
      begin
        plaintext = cipher.update(ciphertext) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise DecryptError, "authentication failed"
      end

      # Advance the replay marker only after a record authenticates, so a forged
      # high-nonce packet can't bump it and lock out legitimate traffic.
      @highest_seen = numeric
      plaintext
    end

    # --- text-transport convenience -----------------------------------------
    # SMS and headers carry text, not raw bytes — Base64 a record for those.

    def encrypt_to_base64(plaintext)
      Base64.strict_encode64(encrypt(plaintext))
    end

    def decrypt_from_base64(text)
      decrypt(Base64.strict_decode64(text))
    end

    private

    def ensure_ready
      raise HandshakeError, "handshake not complete" unless @handshake_complete
    end

    # 12-byte nonce: 4 zero bytes + 8-byte big-endian counter.
    def next_nonce
      n = @send_nonce
      @send_nonce += 1
      [n].pack("Q>").rjust(NONCE_LEN, "\x00").b
    end

    # Minimal big-endian bytes of an OpenSSL::BN, left-padded with zeros to width.
    def int_to_padded_bytes(bn, width)
      int_to_min_bytes(bn).rjust(width, "\x00").b
    end

    # Minimal big-endian bytes (matches the reference's to_s(16)+pack("H*") path,
    # including the odd-length "0" guard).
    def int_to_min_bytes(bn)
      hex = bn.to_s(16)
      hex = "0#{hex}" if hex.bytesize.odd?
      [hex].pack("H*").b
    end
  end

  # Length-prefix framing for *stream* transports (TCP, pipes). A record has no
  # built-in boundary, so on a byte stream you prepend its length.
  module Framing
    HEADER_SIZE = 4
    MAX_FRAME   = 500_000_000

    # Prepend a 4-byte big-endian length to a record.
    def self.frame(record)
      record = record.b
      ([record.bytesize].pack("N") + record).b
    end
  end

  # Accumulates stream bytes and yields complete records as they arrive.
  #
  #   parser = Diffie::FrameParser.new
  #   parser.feed(chunk) { |record| session.decrypt(record) }
  #
  # Raises Error if a length header is zero or absurdly large.
  class FrameParser
    def initialize
      @buffer = "".b
    end

    def feed(chunk)
      @buffer << chunk.b
      while @buffer.bytesize >= Framing::HEADER_SIZE
        length = @buffer[0, Framing::HEADER_SIZE].unpack1("N")
        raise Error, "frame length out of range (#{length})" if length.zero? || length > Framing::MAX_FRAME
        break if @buffer.bytesize < Framing::HEADER_SIZE + length

        record = @buffer[Framing::HEADER_SIZE, length]
        @buffer = @buffer[(Framing::HEADER_SIZE + length)..].b
        yield record
      end
      nil
    end
  end
end
