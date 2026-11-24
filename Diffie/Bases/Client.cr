require "socket"
require "big"
require "digest/sha512"
require "openssl/hmac"

# require "securerandom"

class Client
  @socket : TCPSocket?
  @reader_thread : Thread?
  @id : String
  @on_connect_handlers : Array(Proc(String, Nil))
  @on_message_handlers : Array(Proc(String, Bytes, Nil))
  @on_disconnect_handlers : Array(Proc(String, Nil))

  def initialize(@host : String, @port : Int32)
    @socket = nil
    @reader_thread = nil
    @id = Random::Secure.hex(8)

    # Event handlers
    @on_connect_handlers = [] of Proc(String, Nil)
    @on_message_handlers = [] of Proc(String, Bytes, Nil)
    @on_disconnect_handlers = [] of Proc(String, Nil)

    # Generator : g
    # Prime : prime
    # KA : Random Private Key
    @g = BigInt.new(2)
    @prime = BigInt.new("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
    @aesKey = Bytes.new(32)
    @hmacKey = Bytes.new(32)
  end

  # ---------------------------
  # Event Registration
  # ---------------------------

  def on_connect(&block : String -> Nil) : Nil
    @on_connect_handlers << block
  end

  def on_message(&block : String, Bytes -> Nil) : Nil
    @on_message_handlers << block
  end

  def on_disconnect(&block : String -> Nil) : Nil
    @on_disconnect_handlers << block
  end

  # ---------------------------
  # Emitters
  # ---------------------------

  private def emit_connect
    @on_connect_handlers.each { |h| h.call(@id) }
  end

  private def emit_message(data : Bytes)
    @on_message_handlers.each { |h| h.call(@id, data) }
  end

  private def emit_disconnect
    @on_disconnect_handlers.each { |h| h.call(@id) }
  end

  def powmod(b : BigInt, x : BigInt, m : BigInt) : BigInt
    r = 1.to_big_i; b = b.to_big_i
    while x > 0
      r = (r * b) % m if x.odd?
      b = (b * b) % m
      x >>= 1
    end
    r
  end

  def memshuffle(ptr : Pointer(UInt8), size : Int)
    size.times do |i|
      ptr[i] = (Random.new.random_bytes(1)[0] & 0x7F) + 0x20 # printable ASCII
    end
  end

  # ---------------------------
  # Connect
  # ---------------------------

  def connect : UInt8
    begin
      @socket = TCPSocket.new(@host, @port)

      if @socket.nil?
        return UInt8.new(1)
      end
      # Generate private key
      priv_bytes = Bytes.new(32)
      Random::Secure.random_bytes(priv_bytes)
      priv = BigInt.new(priv_bytes.hexstring, 16)

      # Compute public key
      pub = powmod(@g, priv, @prime)

      pub_hex = pub.to_s(16)
      pub_hex = "0#{pub_hex}" if pub_hex.size.odd?

      # Ruby: [hex].pack("H*")
      pub_bytes = pub_hex.hexbytes

      # Ruby: rjust(256, "\x00")
      padded = Bytes.new(256, 0u8)
      padded[(256 - pub_bytes.size), pub_bytes.size].copy_from(pub_bytes)

      @socket.not_nil!.write(padded)
      # @socket.write(padded)

      client_key = Bytes.new(256)
      @socket.not_nil!.read_fully(client_key)
      # Convert binary -> BigInt
      peer_pub = BigInt.new(client_key.hexstring, 16)

      # Compute shared secret
      secret = powmod(peer_pub, priv, @prime)

      
      # Convert to bytes (Ruby style)
      secret_hex = secret.to_s(16)
      
      
      secret_hex = "0#{secret_hex}" if secret_hex.size.odd?
      # puts "Secret: #{secret_hex}"
      secret_bytes = secret_hex.hexbytes

      # Finish-De-Allocation

      # KDF
      kdf = Digest::SHA512.digest(secret_bytes)

      aes_key = kdf[0, 32]
      hmac_key = kdf[32, 32]
      puts "AES-KEY: #{aes_key.hexstring}"
      puts "HMAC-KEY: #{hmac_key.hexstring}"

      # puts aes_key.hexstring
      # puts hmac_key.hexstring

      # memshuffle(priv_bytes.to_unsafe, priv_bytes.size)
      # memshuffle(secret_bytes.to_unsafe, secret_bytes.size)
      # memshuffle(kdf.to_unsafe, kdf.size)

      @aesKey = aes_key
      @hmacKey = hmac_key
      

      # puts "AES-KEY #{aes_key}"
      # puts "HMAC-Key #{hmac_key}"
      
      emit_connect
      start_reader

      return UInt8.new(0)
    ensure
      memshuffle(priv_bytes.to_unsafe, priv_bytes.size) if priv_bytes
      memshuffle(secret_bytes.to_unsafe, secret_bytes.size) if secret_bytes
      memshuffle(kdf.to_unsafe, kdf.size) if kdf
      UInt8.new(2)
    end
  end

  # ---------------------------
  # Background Reader
  # ---------------------------

  # 0 = Success
  # 1 = Failed
  def start_reader
  socket = @socket.not_nil!

  @reader_thread = Thread.new do
    buffer = Bytes.new(4096)
    accumulator = Bytes.new(0)

    
    begin
      loop do
        bytes_read = socket.read(buffer)
        break if bytes_read == 0
        
        chunk = buffer[0, bytes_read]
        accumulator += chunk
        puts "[RECIEVED CHUNK] #{chunk.hexstring} (#{chunk.size} bytes)"

        while accumulator.size >= 4
          # ---- READ LENGTH ----
          length = (
            (accumulator[0].to_u32 << 24) |
            (accumulator[1].to_u32 << 16) |
            (accumulator[2].to_u32 << 8)  |
            accumulator[3].to_u32
          )

          break if accumulator.size < 4 + length

          packet = accumulator[4, length]
          accumulator = accumulator[(4 + length)...]

          puts "[PACKET LEN] #{length}"
            

          puts "Accum size: #{accumulator.size}, packet length: #{length}"
          puts "Packet bytes: #{packet.hexstring}"

          begin
            if @aesKey && @hmacKey
              aes_key = @aesKey.not_nil!
              hmac_key = @hmacKey.not_nil!

              iv = packet[0, 16]
              hmac = packet[-32, 32]
              encrypted = packet[16...(packet.size - 32)]

              expected_hmac = OpenSSL::HMAC.digest(
                :sha256,
                hmac_key,
                iv + encrypted
              )

              

              if hmac != expected_hmac
                puts "HMAC ERROR"
                next
              end

              cipher = OpenSSL::Cipher.new("AES-256-CBC")
              cipher.decrypt
              cipher.key = aes_key
              cipher.iv = iv

              decrypted = cipher.update(encrypted) + cipher.final

              emit_message(decrypted)
            else
              emit_message(packet)
            end
          rescue ex
            puts "Decrypt error: #{ex.message}"
          end
        end
      end
    rescue ex
      puts "Reader error: #{ex.message}"
    ensure
      socket.close rescue nil
      emit_disconnect
    end
  end
end

  # def start_reader : Int8
  #   socket = @socket.not_nil!

  #   @reader_thread = Thread.new do
  #     buffer = Bytes.new(4096)

  #     # loop do
  #     #   bytes = socket.read(buffer)
  #     #   break if bytes == 0

  #     #   emit_message(buffer[0, bytes])
  #     # end

  #   rescue e
  #     # puts "[CLIENT ERROR] #{e.message}"
  #   ensure
  #     socket.close rescue nil
  #     emit_disconnect
  #   end
  #   return Int8.new(0)
  # end

  # ---------------------------
  # Send Data
  # ---------------------------
  def send(data : Bytes)
  socket = @socket.not_nil!

  if @aesKey && @hmacKey
    aes_key = @aesKey.not_nil!
    hmac_key = @hmacKey.not_nil!

    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt

    iv = Random::Secure.random_bytes(16)

    cipher.key = aes_key
    cipher.iv = iv
    # cipher.padding = true


    encrypted = cipher.update(data) + cipher.final

    hmac = OpenSSL::HMAC.digest(
      :sha256,
      hmac_key,
      iv + encrypted
    )

    packet = iv + encrypted + hmac

    # ---- LENGTH PREFIX ----
    length = packet.size.to_u32
    header = Bytes[
      (length >> 24).to_u8,
      (length >> 16).to_u8,
      (length >> 8).to_u8,
      length.to_u8
    ]


    puts "SENDING PACKET: #{packet.hexstring} (#{packet.size} bytes)"

    socket.write(
      header + packet
    )
#     socket.write(header)

  #   socket.write(packet)

  else
    socket.write(data)
  end
end

  # def send(data : Bytes) : UInt8
  #   begin
  #     @socket.try &.write(data)
  #     return UInt8.new(0)
  #   rescue exception
  #     return UInt8.new(1)
  #   end
  # end

  # ---------------------------
  # Disconnect
  # ---------------------------

  def disconnect
    @socket.try &.close
  end
end

client = Client.new("127.0.0.1", 8080)

client.on_connect do |id|
  puts "[+] Connected (#{id})"
  client.send("Hello World".to_slice)
end

client.on_message do |id, data|
  puts "[#{id}] Received: #{String.new(data)}"
end

client.on_disconnect do |id|
  puts "[-] Disconnected (#{id})"
end

client.connect


loop do
  input = gets
  input = input.to_s
  client.send(input.to_slice)
end
