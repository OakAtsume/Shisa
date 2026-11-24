require "socket"
require "securerandom"
require "openssl"

class Client
  def initialize(host, port)
    @host = host
    @port = port
    @events = {
      onConnect: [],
      onMessage: [],
      onDisconnect: [],
    }
    @socket = nil
    @reader_thread = nil
    @id = SecureRandom.hex(8)
    prime_hex = <<~HEX.delete("\n")
      FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
      29024E088A67CC74020BBEA63B139B22514A08798E3404DD
      EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
      E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
    HEX

    @prime = OpenSSL::BN.new(prime_hex, 16)
    @g = OpenSSL::BN.new("2")
    @aesKey = nil
    @hmacKey = nil
  end

  # ---------------------------
  # Event System
  # ---------------------------

  def on(event, &block)
    @events[event] << block
  end

  def emit(event, *args)
    @events[event].each { |handler| handler.call(*args) }
  end

  # ---------------------------
  # Connect
  # ---------------------------

  def connect
    @socket = TCPSocket.new(@host, @port)
    privKey = OpenSSL::BN.rand(256)
    pub = @g.mod_exp(privKey, @prime)
    pub_bytes = pub.to_s(16)
    pub_bytes = "0#{pub_bytes}" if pub_bytes.length.odd?
    pub_bytes = [pub_bytes].pack("H*")
    pub_bytes = pub_bytes.rjust(256, "\x00")
    @socket.write(pub_bytes)


    clientKey = @socket.read(256)
    peer_pub = OpenSSL::BN.new(clientKey, 2)

    secret = peer_pub.mod_exp(privKey, @prime)
    secret_bytes = secret.to_s(16)
    secret_bytes = "0#{secret_bytes}" if secret_bytes.length.odd?
    secret_bytes = [secret_bytes].pack("H*")

    # KDF
    kdf = Digest::SHA512.digest(secret_bytes)

    aes_key = kdf[0, 32]
    hmac_key = kdf[32, 32]

    puts aes_key.unpack1("H*")
    puts hmac_key.unpack1("H*")

    @aesKey = aes_key
    @hmacKey = hmac_key

    emit(:onConnect, @id)

    start_reader
  end

  # ---------------------------
  # Background Reader
  # ---------------------------

  def start_reader
    @reader_thread = Thread.new do
      loop do
        data = @socket.recv(4096)
        break if data.nil? || data.empty?

        begin
          if @aesKey && @hmacKey
            iv = data[0, 16]
            hmac = data[-32, 32]
            encrypted = data[16...-32]
            expected_hmac = OpenSSL::HMAC.digest("SHA256", @hmacKey, iv + encrypted)
            if hmac != expected_hmac
              puts "[HMAC ERROR] Invalid HMAC for message from #{@id}"
              next
            end
            cipher = OpenSSL::Cipher.new("AES-256-CBC")
            cipher.decrypt
            cipher.key = @aesKey
            cipher.iv = iv
            decrypted = cipher.update(encrypted) + cipher.final
            emit(:onMessage, @id, decrypted)
          else
            emit(:onMessage, @id, data)
          end

        rescue => e
          puts "[DECRYPTION ERROR] #{e.message}"
          puts "[DECRYPTION ERROR] #{e.backtrace.join("\n")}"
        end
      end
    rescue => e
      puts "[CLIENT ERROR] #{e.message}"
    ensure
      @socket.close rescue nil
      emit(:onDisconnect, @id)
    end
  end
  

  # ---------------------------
  # Send Data
  # ---------------------------

  def send(data)
    if @aesKey && @hmacKey
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.encrypt
      iv = OpenSSL::Random.random_bytes(16)
      cipher.key = @aesKey
      cipher.iv = iv
      encrypted = cipher.update(data) + cipher.final
      hmac = OpenSSL::HMAC.digest("SHA256", @hmacKey, iv + encrypted)
      data = iv + encrypted + hmac
    end
    @socket.write(data)
  end

  # ---------------------------
  # Disconnect
  # ---------------------------

  def disconnect
    @socket.close rescue nil
  end
end

client = Client.new("127.0.0.1", 8080)

client.on(:onConnect) do |id|
  puts "[+] Connected (#{id})"
end

client.on(:onMessage) do |id, data|
  puts "[#{id}] Received: #{data.inspect}"
  client.send("Echo: #{data}")
  
end

client.on(:onDisconnect) do |id|
  puts "[-] Disconnected (#{id})"
end

client.connect

loop do
  i = gets.chomp
  break if i.downcase == "exit"
  client.send(i)
end
