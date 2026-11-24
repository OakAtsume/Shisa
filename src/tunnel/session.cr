require "base64"
require "../crypto/curve25519"
require "./aead"
require "./hkdf"
require "openssl/digest"

module Diffie
  PUBKEY_BYTES = 32
  HKDF_INFO    = "glob/v2"
  NONCE_LEN    = 12
  TAG_LEN      = 16

  AUTH_CHALLENGE = 0x01_u8
  AUTH_RESPONSE  = 0x02_u8
  AUTH_MSG_SIZE  = 1 + 32 + 64 # type + ed25519 pubkey + signature

  enum Role
    Client
    Server
  end

  class Error < Exception; end
  class HandshakeError < Error; end
  class ReplayError < Error; end
  class DecryptError < Error; end
  class AuthError < Error; end

  class Session
    getter role : Role
    getter? handshake_complete : Bool
    getter? authenticated : Bool

    def initialize(@role : Role)
      @x25519 = Crypto::X25519::KeyPair.new
      @peer_x25519_pub = Bytes.new(0)
      @send_key = Bytes.new(32)
      @recv_key = Bytes.new(32)
      @send_nonce = 1_u64
      @highest_seen = 0_u64
      @handshake_complete = false
      @authenticated = false
    end

    # --- key exchange --------------------------------------------------------

    def local_public_key : Bytes
      @x25519.public_key
    end

    def complete_handshake(peer_public_key : Bytes) : Nil
      unless peer_public_key.size == PUBKEY_BYTES
        raise HandshakeError.new("peer public key must be #{PUBKEY_BYTES} bytes, got #{peer_public_key.size}")
      end

      @peer_x25519_pub = peer_public_key.dup
      secret = @x25519.derive(peer_public_key)
      okm = HKDF.derive(secret, "", HKDF_INFO, 64)
      c2s = okm[0, 32]
      s2c = okm[32, 32]

      case @role
      in Role::Client then @send_key, @recv_key = c2s, s2c
      in Role::Server then @send_key, @recv_key = s2c, c2s
      end
      @handshake_complete = true
    end

    # --- mutual authentication -----------------------------------------------

    def create_auth(identity : Crypto::Ed25519::KeyPair) : Bytes
      transcript = auth_transcript
      signature = identity.sign(transcript)
      msg = Bytes.new(AUTH_MSG_SIZE)
      msg[0] = @role == Role::Server ? AUTH_CHALLENGE : AUTH_RESPONSE
      identity.public_key.copy_to(msg[1, 32])
      signature.copy_to(msg[33, 64])
      msg
    end

    def verify_auth(msg : Bytes, trusted_keys : Array(Bytes)) : Bytes
      raise AuthError.new("auth message must be #{AUTH_MSG_SIZE} bytes") unless msg.size == AUTH_MSG_SIZE

      expected_type = @role == Role::Server ? AUTH_RESPONSE : AUTH_CHALLENGE
      raise AuthError.new("unexpected auth message type") unless msg[0] == expected_type

      peer_ed_pub = msg[1, 32]
      signature = msg[33, 64]

      unless trusted_keys.any? { |k| k == peer_ed_pub }
        raise AuthError.new("peer identity not in trusted key list")
      end

      transcript = peer_auth_transcript
      unless Crypto::Ed25519.verify(peer_ed_pub, transcript, signature)
        raise AuthError.new("signature verification failed")
      end

      @authenticated = true
      peer_ed_pub
    end

    # --- messaging -----------------------------------------------------------

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

    def decrypt(record : Bytes) : Bytes
      ensure_ready
      if record.size < NONCE_LEN + TAG_LEN
        raise DecryptError.new("record too short (#{record.size} bytes)")
      end

      nonce = record[0, NONCE_LEN]
      body = record[NONCE_LEN, record.size - NONCE_LEN]
      ciphertext = body[0, body.size - TAG_LEN]
      tag = body[body.size - TAG_LEN, TAG_LEN]

      numeric = 0_u64
      nonce.each { |b| numeric = (numeric << 8) | b.to_u64 }
      raise ReplayError.new("nonce did not increase (#{numeric} <= #{@highest_seen})") if numeric <= @highest_seen

      plaintext = AEAD.open(@recv_key, nonce, ciphertext, tag)
      raise DecryptError.new("authentication failed") if plaintext.nil?

      @highest_seen = numeric
      plaintext
    end

    def encrypt_to_base64(plaintext) : String
      Base64.strict_encode(encrypt(plaintext))
    end

    def decrypt_from_base64(text : String) : Bytes
      decrypt(Base64.decode(text))
    end

    private def ensure_ready
      raise HandshakeError.new("handshake not complete") unless @handshake_complete
    end

    private def next_nonce : Bytes
      n = @send_nonce
      @send_nonce += 1
      nonce = Bytes.new(NONCE_LEN, 0_u8)
      IO::ByteFormat::BigEndian.encode(n, nonce[4, 8])
      nonce
    end

    private def auth_transcript : Bytes
      role_byte = @role == Role::Server ? AUTH_CHALLENGE : AUTH_RESPONSE
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(Bytes[role_byte])
      digest.update(@x25519.public_key)
      digest.update(@peer_x25519_pub)
      digest.final
    end

    private def peer_auth_transcript : Bytes
      peer_role_byte = @role == Role::Server ? AUTH_RESPONSE : AUTH_CHALLENGE
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(Bytes[peer_role_byte])
      digest.update(@peer_x25519_pub)
      digest.update(@x25519.public_key)
      digest.final
    end
  end

  module Framing
    extend self

    HEADER_SIZE = 4
    MAX_FRAME   = 500_000_000

    def frame(record : Bytes) : Bytes
      framed = Bytes.new(HEADER_SIZE + record.size)
      IO::ByteFormat::BigEndian.encode(record.size.to_u32, framed[0, HEADER_SIZE])
      record.copy_to(framed[HEADER_SIZE, record.size])
      framed
    end
  end

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

      rest = bytes[offset, bytes.size - offset]
      @buffer.clear
      @buffer.write(rest)
    end
  end
end
