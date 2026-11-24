require "big"

class Asem
  def initialize
  end

  def powmod(base : Int32, exponent : BigInt, modulus : BigInt)
    result = 1.to_big_i
    base = base.to_big_i

    while exponent > 0
      result = (result * base) % modulus if exponent.odd?
      base = (base * base) % modulus
      exponent >>= 1
    end

    result
  end

  def modInverse(a : BigInt, m : BigInt) : BigInt
    m0 = m
    x0 = 0.to_big_i
    x1 = 1.to_big_i

    return 0.to_big_i if m == 1

    while a > 1
      q = a // m
      m, a = a % m, m
      x0, x1 = x1 - q * x0, x0
    end

    x1 += m0 if x1 < 0
    x1
  end

  def repackStringHexToBytes(input : String) : Slice(UInt8)
    input.hexbytes
  end

  def repackBytesToString(input : Slice(UInt8) | Array(BigInt)) : String
    String.build do |io|
      input.each { |byte| io.write_byte(byte.to_u8) }
    end
  end

  def encrypt(msg : String | Slice(UInt8), key : BigInt, prime : BigInt, pack : Bool = false) : String
    if !(msg.is_a?(Slice(UInt8)) || msg.is_a?(String))
      puts("Given: #{typeof(msg)}")
      raise("Invalid type given!")
    end

    if msg.is_a?(Slice(UInt8))
      msg = repackBytesToString(msg)
    end

    io = IO::Memory.new
    msg.each_byte do |byte|
      enc = (byte.to_big_i * key) % prime
      io.write_bytes(enc.to_u64, IO::ByteFormat::LittleEndian)
    end
    raw = io.to_slice
    pack ? raw.hexstring : String.new(raw)
  end

  def decrypt(msg : String | Slice(UInt8), key : BigInt, prime : BigInt, pack : Bool = false) : String
    if msg.is_a?(String)
      encrypted_bytes = pack ? repackStringHexToBytes(msg) : msg.to_slice
    elsif msg.is_a?(Slice(UInt8))
      encrypted_bytes = msg
    else
      raise("Invalid type given!")
    end

    decrypted = Array(BigInt).new

    io = IO::Memory.new(encrypted_bytes)
    while io.pos < io.size
      decrypted << io.read_bytes(UInt64, IO::ByteFormat::LittleEndian).to_big_i
    end

    inverse = modInverse(powmod(2, key, prime), prime)

    decrypted_bytes = decrypted.map { |val| (val * inverse) % prime }

    repackBytesToString(decrypted_bytes)
  end
end

def cyclexor(data : Bytes, key : Bytes, state : UInt8) : Bytes
  out = Bytes.new(data.size)
  prev = state

  data.each_with_index do |byte, i|
    k = key[i % key.size]

    # mix position + previous output
    v = byte ^ k ^ (i & 0xff).to_u8 ^ prev

    out[i] = v
    prev = v
  end

  out
end
