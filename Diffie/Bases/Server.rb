require "socket"
require "securerandom"
require "thread"
require "openssl"

class Server
  def initialize(port)
    @threads = []
    @clients = {} # track client data
    @events = {
      onConnect: [],
      onDisconnect: [],
      onMessage: [],
    }

    @server = TCPServer.new(port)
    puts "Server listening on port #{port}"
    prime_hex = <<~HEX.delete("\n")
      FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
      29024E088A67CC74020BBEA63B139B22514A08798E3404DD
      EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
      E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
    HEX

    @prime = OpenSSL::BN.new(prime_hex, 16)
    @generator = OpenSSL::BN.new("2")
  end

  attr_reader :clients

  # ---------------------------
  # Event System              #
  # ---------------------------
  def on(event, &block)
    @events[event] << block
  end

  def emit(event, *args)
    @events[event].each { |handler| handler.call(*args) }
  end
  

  def aesDecrypt(key, data, hmacKey)
    # <16-byte IV>              # AES IV
    # <n-byte AES ciphertext>   # encrypted payload
    # <32-byte HMAC>            # SHA256 HMAC

    hmac = data[-32..-1]
    ciphertext = data[16...-32]
    iv = data[0, 16]
    checkHmac = OpenSSL::HMAC.digest("SHA256", hmacKey, iv + ciphertext)

    if checkHmac != hmac
      puts "HMAC verification failed Ours(#{checkHmac.unpack1("H*")}) != Theirs(#{hmac.unpack1("H*")})"
    end

    # Decrypt the AES ciphertext
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    # cipher.padding = 1

    plaintext = cipher.update(ciphertext) + cipher.final
    plaintext
  end

  def aesEncrypt(key, plaintext, hmacKey)
    # Generate a random 16-byte IV
    iv = OpenSSL::Random.random_bytes(16)

    # Encrypt the plaintext using AES-256-CBC
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    # cipher.padding = 1

    ciphertext = cipher.update(plaintext) + cipher.final

    # Compute HMAC of IV + ciphertext
    hmac = OpenSSL::HMAC.digest("SHA256", hmacKey, iv + ciphertext)

    # Return IV + ciphertext + HMAC
    iv + ciphertext + hmac
  end




  # ---------------------------
  # Start Server              #
  # ---------------------------
  def start
    loop do
      socket = @server.accept
      client_id = SecureRandom.hex(8)

      # Initialize client data
      @clients[client_id] = {
        socket: socket,
        alive: true,
        write_mutex: Mutex.new,
        host: [
          socket.peeraddr[3],
          socket.peeraddr[4],
        ],
        session: Random.uuid(),
        encryption: {
          active: false,
          aesKey: nil,
          hmacKey: nil,
        },
      }

      # Perform Diffie-Hellman Key Exchange
      begin
        privKey = OpenSSL::BN.rand(256)
        pub = @generator.mod_exp(privKey, @prime)
        pub_bytes = pub.to_s(16)
        pub_bytes = "0#{pub_bytes}" if pub_bytes.length.odd?
        pub_bytes = [pub_bytes].pack("H*")
        pub_bytes = pub_bytes.rjust(256, "\x00")
        socket.write(pub_bytes)

        clientKey = socket.read(256)
        peer_pub = OpenSSL::BN.new(clientKey, 2)
        secret = peer_pub.mod_exp(privKey, @prime)
        secret_bytes = secret.to_s(16)
        secret_bytes = "0#{secret_bytes}" if secret_bytes.length.odd?
        secret_bytes = [secret_bytes].pack("H*")

        # Turn it into a BN to print it, then back to bytes for KDF
        # puts "Shared Secret: #{secret.to_s(16)}"


        # KDF
        kdf = Digest::SHA512.digest(secret_bytes)

        aes_key = kdf[0, 32]
        hmac_key = kdf[32, 32]

        # puts aes_key.unpack1("H*")

        # puts hmac_key.unpack1("H*")
        puts Digest::SHA256.digest(secret_bytes).unpack1("H*")

        puts "AES Key: #{aes_key.unpack1("H*")}"
        puts "HMAC Key: #{hmac_key.unpack1("H*")}"
        @clients[client_id][:encryption] = {
          active: true,
          aesKey: aes_key,
          hmacKey: hmac_key,
        }
      rescue => e
        puts "[HANDSHAKE ERROR] #{client_id}: #{e.message}"
        disconnect(client_id)
        next
      end

      emit(:onConnect, client_id, socket)

      thread = Thread.new do
        handle_client(client_id)
      end

      @threads << thread
    end
  end

  # ---------------------------
  # Safe Write
  # ---------------------------
  def write(client_id, data)
  client = @clients[client_id]
  return false unless client && client[:alive]

  client[:write_mutex].synchronize do
    return false unless client[:alive]

    if client[:encryption][:active]
      data = aesEncrypt(
        client[:encryption][:aesKey],
        data,
        client[:encryption][:hmacKey]
      )
    end

    # ---- LENGTH PREFIX ----
    header = [data.bytesize].pack("N")
    puts "SENDING PACKET: #{data.unpack1("H*")} (#{data.size} bytes)"
    client[:socket].write(header + data)
  end

  true
rescue => e
  puts "[WRITE ERROR] #{client_id}: #{e.message}"
  disconnect(client_id)
  false
end
end


  # ---------------------------
  # Disconnect
  # ---------------------------
  def disconnect(client_id)
    client = @clients[client_id]
    return unless client && client[:alive]

    client[:alive] = false
    begin
      client[:socket].close unless client[:socket].closed?
    rescue
    end
    emit(:onDisconnect, client_id)
    @clients.delete(client_id)
  end

  # ---------------------------
  # Client Handler
  # ---------------------------
  def handle_client(client_id)
  client = @clients[client_id]
  socket = client[:socket]

  buffer = "".b

  loop do
    break unless client[:alive]

    chunk = socket.recv(4096).b
    break if chunk.nil? || chunk.empty?

    # Hexdump the chunk for debugging
    puts "[RECEIVED CHUNK] #{chunk.unpack1("H*")} (#{chunk.size} bytes)"

    buffer << chunk

    while buffer.bytesize >= 4
      length = buffer[0,4].unpack1("N")

      puts "[PACKET LEN] #{length}"
              
      break if buffer.bytesize < 4 + length

      packet = buffer[4, length].b
      buffer = buffer[(4 + length)..] || "".b

      puts "RECEIVED RAW: #{packet.size}"

      begin
        data = packet

        if client[:encryption][:active]
          data = aesDecrypt(
            client[:encryption][:aesKey],
            packet,
            client[:encryption][:hmacKey]
          )
        end

        emit(:onMessage, client_id, socket, data)
      rescue => e
        puts "[DECRYPTION ERROR] #{client_id}: #{e.message}"
        break
      end
    end
  end
rescue => e
  puts "[ERROR] #{client_id}: #{e.message}"
ensure
  disconnect(client_id)
end


server = Server.new(8080)

a = ""
server.on(:onConnect) do |client_id, socket|
  puts("New Connection from #{client_id}")
  server.write(client_id, "Welcome, #{client_id}!")
  a = client_id
end

server.on(:onDisconnect) do |client_id|
  puts "Client #{client_id} disconnected"
end

# emit(:onMessage, client_id, socket, data)

server.on(:onMessage) do |client_id, socket, data|
  puts "[#{client_id}] Received: #{data.inspect}"
  server.write(client_id, "Echo: #{data}")
end

ins = Thread.new do
  server.start
end


loop do
  input = gets.chomp!
  # puts input

  server.clients.each_key do |client_id|
    server.write(client_id, "Server Broadcast: #{input}")  
    puts "Sent to #{client_id}"
  end
  if input == "exit"
    ins.kill
    break
  end
end