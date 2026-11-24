# frozen_string_literal: true

require "openssl"
require "securerandom"
require "base64"

module Diffie
  PUBKEY_BYTES = 32
  HKDF_INFO    = "glob/v2"
  NONCE_LEN    = 12
  TAG_LEN      = 16

  AUTH_CHALLENGE = 0x01
  AUTH_RESPONSE  = 0x02
  AUTH_MSG_SIZE  = 1 + 32 + 64

  ROLES = %i[client server].freeze

  class Error < StandardError; end
  class HandshakeError < Error; end
  class ReplayError < Error; end
  class DecryptError < Error; end
  class AuthError < Error; end

  class Session
    attr_reader :role

    def initialize(role)
      raise ArgumentError, "role must be :client or :server" unless ROLES.include?(role)

      @role = role
      @x25519 = OpenSSL::PKey.generate_key("X25519")
      @peer_x25519_pub = nil
      @send_key = nil
      @recv_key = nil
      @send_nonce = 1
      @highest_seen = 0
      @handshake_complete = false
      @authenticated = false
    end

    def handshake_complete?
      @handshake_complete
    end

    def authenticated?
      @authenticated
    end

    # --- key exchange --------------------------------------------------------

    def local_public_key
      @x25519.raw_public_key
    end

    def complete_handshake(peer_public_key)
      peer_public_key = peer_public_key.b
      unless peer_public_key.bytesize == PUBKEY_BYTES
        raise HandshakeError, "peer public key must be #{PUBKEY_BYTES} bytes, got #{peer_public_key.bytesize}"
      end

      @peer_x25519_pub = peer_public_key
      peer_pkey = OpenSSL::PKey.new_raw_public_key("X25519", peer_public_key)
      secret = @x25519.derive(peer_pkey)

      okm = OpenSSL::KDF.hkdf(secret, salt: "", info: HKDF_INFO, length: 64, hash: "SHA256")
      c2s = okm[0, 32]
      s2c = okm[32, 32]

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

    # --- mutual authentication -----------------------------------------------

    def create_auth(identity_key)
      transcript = auth_transcript
      signature = identity_key.sign(nil, transcript)
      type_byte = (@role == :server ? AUTH_CHALLENGE : AUTH_RESPONSE).chr.b
      (type_byte + identity_key.raw_public_key + signature).b
    end

    def verify_auth(msg, trusted_keys)
      msg = msg.b
      raise AuthError, "auth message must be #{AUTH_MSG_SIZE} bytes" unless msg.bytesize == AUTH_MSG_SIZE

      expected_type = @role == :server ? AUTH_RESPONSE : AUTH_CHALLENGE
      raise AuthError, "unexpected auth message type" unless msg.getbyte(0) == expected_type

      peer_ed_pub = msg[1, 32]
      signature = msg[33, 64]

      unless trusted_keys.any? { |k| k == peer_ed_pub }
        raise AuthError, "peer identity not in trusted key list"
      end

      transcript = peer_auth_transcript
      peer_pkey = OpenSSL::PKey.new_raw_public_key("ED25519", peer_ed_pub)
      unless peer_pkey.verify(nil, signature, transcript)
        raise AuthError, "signature verification failed"
      end

      @authenticated = true
      peer_ed_pub
    end

    # --- messaging -----------------------------------------------------------

    def encrypt(plaintext)
      ensure_ready
      nonce = next_nonce

      cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
      cipher.key = @send_key
      cipher.iv = nonce
      ciphertext = cipher.update(plaintext.b) + cipher.final
      tag = cipher.auth_tag

      (nonce + ciphertext + tag).b
    end

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

      @highest_seen = numeric
      plaintext
    end

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

    def next_nonce
      n = @send_nonce
      @send_nonce += 1
      [n].pack("Q>").rjust(NONCE_LEN, "\x00").b
    end

    def auth_transcript
      role_byte = (@role == :server ? AUTH_CHALLENGE : AUTH_RESPONSE).chr.b
      OpenSSL::Digest::SHA256.digest(role_byte + local_public_key + @peer_x25519_pub)
    end

    def peer_auth_transcript
      peer_role_byte = (@role == :server ? AUTH_RESPONSE : AUTH_CHALLENGE).chr.b
      OpenSSL::Digest::SHA256.digest(peer_role_byte + @peer_x25519_pub + local_public_key)
    end
  end

  module Framing
    HEADER_SIZE = 4
    MAX_FRAME   = 500_000_000

    def self.frame(record)
      record = record.b
      ([record.bytesize].pack("N") + record).b
    end
  end

  class FrameParser
    def initialize
      @buffer = "".b
    end

    def pending_bytes
      @buffer.bytesize
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
