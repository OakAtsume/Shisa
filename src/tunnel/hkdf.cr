require "openssl/hmac"

# HKDF (RFC 5869) over HMAC-SHA256. Crystal's stdlib ships HMAC but not HKDF,
# so we implement the extract-then-expand construction directly. Output is
# byte-identical to Ruby's `OpenSSL::KDF.hkdf(..., hash: "SHA256")`.
module HKDF
  extend self

  HASH_LEN = 32

  def derive(ikm : Bytes, salt : Bytes, info : Bytes, length : Int32) : Bytes
    raise "length too large" if length > 255 * HASH_LEN

    # Extract: PRK = HMAC(salt, IKM). An empty salt defaults to HASH_LEN zeros.
    salt = Bytes.new(HASH_LEN, 0_u8) if salt.empty?
    prk = OpenSSL::HMAC.digest(:sha256, salt, ikm)

    # Expand: T(i) = HMAC(PRK, T(i-1) || info || i)
    okm = Bytes.new(length)
    previous = Bytes.empty
    counter = 1_u8
    offset = 0
    while offset < length
      block = IO::Memory.new
      block.write(previous)
      block.write(info)
      block.write_byte(counter)
      previous = OpenSSL::HMAC.digest(:sha256, prk, block.to_slice)

      take = Math.min(previous.size, length - offset)
      previous[0, take].copy_to(okm[offset, take])
      offset += take
      counter &+= 1
    end
    okm
  end

  def derive(ikm : Bytes, salt : String, info : String, length : Int32) : Bytes
    derive(ikm, salt.to_slice, info.to_slice, length)
  end
end
