require "rfc8439"

# ChaCha20-Poly1305 AEAD (RFC 8439 / IETF), wire-compatible with OpenSSL's
# "chacha20-poly1305" cipher — which is what the Ruby server/client use.
#
# The rfc8439 shard ships a high-level `Crypto::AeadChacha20Poly1305`, but that
# class writes the *entire Poly1305 MAC buffer* (padded ciphertext + length
# footer) to its IO rather than a bare ciphertext, so it is only round-trippable
# with itself. To talk to OpenSSL we build the AEAD from the primitives, which
# gives us a ciphertext exactly the length of the plaintext plus a 16-byte tag.
module AEAD
  extend self

  TAG_SIZE   = 16
  BLOCK_SIZE = 16

  # Encrypts `plaintext` and returns {ciphertext, 16-byte tag}.
  # `nonce` must be 12 bytes, `key` 32 bytes. No additional authenticated data.
  def seal(key : Bytes, nonce : Bytes, plaintext : Bytes) : {Bytes, Bytes}
    # Keystream for the message starts at block counter 1 (counter 0 is reserved
    # for deriving the one-time Poly1305 key).
    ciphertext = Crypto::ChaCha20.new(key, nonce, 1_u32).encrypt(plaintext)
    tag = mac(key, nonce, ciphertext)
    {ciphertext, tag}
  end

  # Verifies `tag` and decrypts `ciphertext`. Returns the plaintext, or `nil`
  # if authentication fails (tampering / wrong key / wrong nonce).
  def open(key : Bytes, nonce : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes?
    expected = mac(key, nonce, ciphertext)
    return nil unless secure_compare(expected, tag)
    # ChaCha20 is symmetric: encrypting the ciphertext recovers the plaintext.
    Crypto::ChaCha20.new(key, nonce, 1_u32).encrypt(ciphertext)
  end

  # Poly1305 tag over: ciphertext || pad16 || le64(aad_len = 0) || le64(ct_len)
  private def mac(key : Bytes, nonce : Bytes, ciphertext : Bytes) : Bytes
    poly = Crypto::Poly1305.chacha20(key, nonce) # one-time key from counter-0 block
    poly.update(ciphertext)

    pad = ciphertext.size % BLOCK_SIZE
    poly.update(Bytes.new(BLOCK_SIZE - pad, 0_u8)) if pad != 0

    footer = Bytes.new(16, 0_u8)
    IO::ByteFormat::LittleEndian.encode(0_u64, footer[0, 8])                       # aad length
    IO::ByteFormat::LittleEndian.encode(ciphertext.size.to_u64, footer[8, 8])     # ciphertext length
    poly.update(footer)

    poly.final
  end

  # Constant-time comparison so a bad tag can't be distinguished by timing.
  private def secure_compare(a : Bytes, b : Bytes) : Bool
    return false if a.size != b.size
    diff = 0_u8
    a.size.times { |i| diff |= a[i] ^ b[i] }
    diff == 0
  end
end
