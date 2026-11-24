require "socket"
require "securerandom"
require "thread"
require "openssl"
require "timeout"

class SocketServer
  def initialize(port)
    @threads = []
    @clients = {}
    @events = {
      onConnect: [],
      onDisconnect: [],
      onMessage: [],
      onProtocolError: [],
      onHandshakeError: [],
    }
    # onProtocolError
    # client_id, socket, ERROR_ID, Message
    # ERROR_ID
    # 0 = Replay Attack detected
    # 1 = Unable to decrypt the ciphertext
    # 2 = Length mis-match, possible packet forge
    # 3 = Misc. Please use Message lol

    puts("Server started on port TCP/IP(#{port})")
    @server = TCPServer.new(port)
    @prime = OpenSSL::BN.new("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD29024E088A67CC74020BBEA63B139B22514A08798E3404DDE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",16)
    @generator = OpenSSL::BN.new("2", 10)
  end

  attr_reader :clients

  def on(event, &block)
    @events[event] << block
  end

  def emit(event, *args)
    @events[event].each { |handler| handler.call(*args) }
  end

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

  def handleClient(client_id)
    client = @clients[client_id]
    socket = client[:socket]

    # ChaCha20Poly1305;

    # Packet Struct
    # 4 Byte : Lenght;
    # 12 Byte : Nonce
    # N Byte : Ciphertext + Tag (I guess lol)

    buffer = "".b

    loop do
      # highestNonce = client[:encryption][:highestSeenNonce]

      # if socket.nil? || socket.closed?
      # 	disconnect(client_id)
      # 	return
      # end

      break unless client[:alive]

      begin
        chunk = socket.recv(4096)
        if chunk.nil? || chunk.empty?
          disconnect(client_id)
          break
        end
      rescue => e
        emit(:onProtocolError, client_id, socket, 3, "Generic TCP Error")
        disconnect(client_id)
        break
      end

      chunk.force_encoding("BINARY")
      buffer << chunk

      while buffer.bytesize >= 4
        # Read first 4 bytes. It's the *size* of the packet
        length = buffer[0, 4].unpack1("N")
        # No packet should EVER be larger than 500Mb's, so We will BLOCK if the size is BS
        if length > 500_000_000 || length == 0
          # puts("Frame Blocked; Closing connection for #{client_id}")
          emit(:onProtocolError, client_id, socket, 2, "Message Length was too Big/Small. Either 0 or More than 500Mb's")
          disconnect(client_id)
          return
        end

        # We Skip loop, if we haven't read the entire frame!
        break if buffer.bytesize < (4 + length)

        # Extract the whole frame and remove it from the buffer;
        frame = buffer.slice!(0, 4 + length)

        # if frame.bytesize != length
        # 	puts("Fake Size :(")
        # 	disconnect(client_id)
        # 	return
        # end

        nonce = frame[4, 12] 	# Bytes 4 -> 15 (12 Bytes)
        payload = frame[16..-1] # Rest of the frame, (CipherText + Tag)

        # Poly1305 Appends itself to the *end* of the frame
        ciphertext = payload[0...-16]
        tag = payload[-16..-1]

        # Check Nonce.
        numeric_nonce = nonce.unpack1("H*").to_i(16)
        if numeric_nonce <= @clients[client_id][:encryption][:highestSeenNonce]
          # puts("Replay attack detected; Blocking connection")
          emit(:onProtocolError, client_id, socket, 0, "Possible Packet-Replay attack detected. Connection has been blocked.")
          disconnect(client_id)
          return 0
        end
        @clients[client_id][:encryption][:highestSeenNonce] = numeric_nonce

        # TODO Finish Encrypt/Decrypt function haha;

        # Decrypt Message

        message = decrypt(nonce, client[:encryption][:recvKey], tag, ciphertext)
        if message.nil?
          emit(:onProtocolError, client_id, socket, 1, "Unable to decrypt message from host. Potential broken client or tampering. Connection has been blocked.")
          disconnect(client_id)
          return 0
        end

        emit(:onMessage, client_id, socket, message)
      end
    end
    if buffer.bytesize > 0
      emit(:onProtocolError, client_id, socket, 2, "Connection closed with partial data in buffer (#{buffer.bytesize} bytes).")
    end
  end

  # Returns String of valid
  # Returns NIL on failure
  def decrypt(nonce, key, tag, cipherText)
    cipher = OpenSSL::Cipher.new("chacha20-poly1305")
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag

    begin
      decryptedData = cipher.update(cipherText) + cipher.final
      return decryptedData
    rescue OpenSSL::Cipher::CipherError
      return nil
    end
  end

  def write(client_id, plaintext)
    client = @clients[client_id]
    return false unless client && client[:alive]

    client[:write_mutex].synchronize do
      return false unless client[:alive]
      if client[:encryption][:active]
        # nonce = client[:encryption][:nonce]
        # Setup Nonce and increment by 1
        client[:encryption][:nonce] += 1
        nonce = client[:encryption][:nonce]
        nonceBytes = [nonce].pack("Q>").rjust(12, "\x00")

        # Setup Encryption
        cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt()
        cipher.key = client[:encryption][:sendKey]
        cipher.iv = nonceBytes

        # 3. Encrypt and set the tag
        cipherText = cipher.update(plaintext) + cipher.final
        tag = cipher.auth_tag

        # 4. Frame
        payload = nonceBytes + cipherText + tag
        header = [payload.bytesize].pack("N")

        # 5. Write it out :3

        begin
          client[:socket].write(header + payload)
        rescue => e
          puts("Failed to Write to #{client_id}: #{e.message}")
          disconnect(client_id)
        end
      end
    end
  end

  def start()
    # Use onHandshakeError
    # Structure:
    # host:port, error-id, message
    # error-id's
    # 0 = Connection Early Dropped.
    # 1 = Message too short.
    # 2 = Generic Handshake error. Please check message dump

    loop do
      socket = @server.accept()
      # socket.timeout = 10
      # timeout_val = [10, 0].pack("l_2")
      # socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, timeout_val)

      clientId = SecureRandom.hex(8)
      @clients[clientId] = {
        socket: socket,
        alive: true,
        write_mutex: Mutex.new(),
        host: [
          socket.peeraddr[3],
          socket.peeraddr[4],
        ],
        session: "",
        encryption: {
          active: false,
          sendKey: nil, # server -> client (s2c)
          recvKey: nil, # client -> server (c2s)
          nonce: 0,     # deterministic; separate keys per direction make a random start unnecessary
          highestSeenNonce: 0,
        },
      }
      # begin
      # Start Diffie-Hellman Key-Exchange #
      # Generate a 32 byte key.
      privKey = OpenSSL::BN.rand(256)
      publicKey = @generator.mod_exp(privKey, @prime)
      puts("Our Private Key: #{privKey}")
      puts("Our Public Key: #{publicKey.to_s(16)}")
      publicBytes = publicKey.to_s(16) # Turn into Hex-String
      publicBytes = "0#{publicBytes}" if publicBytes.bytesize.odd? # Guard odd-length: pack("H*") would append a trailing nibble and corrupt the key
      publicBytes = [publicBytes].pack("H*") # Pack into Raw Hex
      publicBytes = publicBytes.rjust(256, "\x00") # Pad to 256 bytes
      # Send over our Public Key.
      socket.write(publicBytes)

      # Now we read the client's key; Should also be 256 bytes.
      # We will also do checks to ensure that it's *actually* 256 bytes;
      begin
        Timeout.timeout(10) do
          clientreply = socket.read(256)
          if clientreply.nil?
            emit(:onHandshakeError, "#{@clients[clientId][:host][0]}:#{@clients[clientId][:host][1]}", 0, "Connection Early dropped :shrug:")
            # raise("Exchange failure; Connection dropped")
            socket.close rescue nil # Don't leak the socket/entry; onConnect never fired so skip onDisconnect
            @clients.delete(clientId)
            next
          end
          if clientreply.bytesize < 256
            emit(:onHandshakeError, "#{@clients[clientId][:host][0]}:#{@clients[clientId][:host][1]}", 1, "Message was less than 256 Bytes.")
            # raise("Exchange failure; only #{clientreply.bytesize} Bytes read. Expected 256 Bytes")
            socket.close rescue nil
            @clients.delete(clientId)
            next
          end

          clientreply.force_encoding("BINARY")

          peerKey = OpenSSL::BN.new(clientreply, 2)
          puts("Their-Key: #{peerKey}")

          secret = peerKey.mod_exp(privKey, @prime)
          secret = secret.to_s(16)
          secret = "0#{secret}" if secret.bytesize.odd?
          secret = [secret].pack("H*")
          puts "Secret: #{secret.unpack1("H*")}"

          # Derive one ChaCha20-Poly1305 key per direction from the shared secret.
          # Separate keys mean the client's and server's nonce counters live in
          # different keyspaces and can never collide (no shared-key reuse).
          okm = OpenSSL::KDF.hkdf(secret, salt: "", info: "diffie/v1", length: 64, hash: "SHA256")
          c2sKey = okm[0, 32]  # client -> server
          s2cKey = okm[32, 32] # server -> client
          puts "Send Key (s2c): #{s2cKey.unpack1("H*")}"
          puts "Recv Key (c2s): #{c2sKey.unpack1("H*")}"

          @clients[clientId][:encryption][:sendKey] = s2cKey
          @clients[clientId][:encryption][:recvKey] = c2sKey
          @clients[clientId][:encryption][:active] = true
          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)

          # IMPORTANT: Start the thread AFTER the handshake succeeds
          t = Thread.new { handleClient(clientId) }
          # socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [0, 0].pack("l_2"))
          # socket.timeout = 0;

          emit(:onConnect, clientId)
          @threads << t
        end
      rescue Timeout::Error
        emit(:onHandshakeError, "#{@clients[clientId][:host][0]}:#{@clients[clientId][:host][1]}", 2, "Handshake timed out after 10s")
        disconnect(clientId)
        next
      rescue => e
        emit(:onHandshakeError, "#{@clients[clientId][:host][0]}:#{@clients[clientId][:host][1]}", 2, "#{e}\n#{e.backtrace.join("\n")}")
        disconnect(clientId)

        # puts("Exception #{e}\n#{e.backtrace.join("\n")}")
        next
      end
    end
  end
end

server = SocketServer.new(8081)

server.on(:onConnect) do |client_id, socket|
  puts("New Connection from #{client_id}")
  server.write(client_id, "Hello! #{client_id}")
end

server.on(:onMessage) do |client_id, socket, data|
  puts("[#{client_id}]: #{data}")
end

server.on(:onDisconnect) do |client_id, socket|
  puts("Lost Connection from #{client_id}")
end

# client_id, socket, ERROR_ID, Message
server.on(:onProtocolError) do |client_id, socket, error_id, message|
  puts("[PROTOCOL-ERROR]: #{client_id} #{error_id} : #{message}")
end

# host:port, error-id, message
server.on(:onHandshakeError) do |host, error_id, message|
  puts("[HANDSHAKE-ERROR]: #{host} #{error_id} #{message} ")
end

serverThread = Thread.new do
  server.start()
end

loop do
  print "> "
  input = gets.chomp
  server.clients.each do |client_id, x|
    server.write(client_id, input)
		
  end
end

# # onProtocolError: [],
#       onHandshakeError: [],
