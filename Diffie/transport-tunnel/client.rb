require "socket"
require "openssl"
require "securerandom"

# --- Configuration (Must match Server) ---

GENERATOR = 2

class SecureClient
  def initialize(host, port)
    @socket = TCPSocket.new(host, port)
    @prime = OpenSSL::BN.new("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD29024E088A67CC74020BBEA63B139B22514A08798E3404DDE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",16)
    @gen = OpenSSL::BN.new("2", 10)

    # State
    @encryption_key = nil
    @send_nonce = SecureRandom.random_number(1..1_000_000)
    @highest_seen_nonce = 0
  end

  def handshake
    puts "Starting Handshake..."
    privKey = OpenSSL::BN.rand(256)
    publicKey = @gen.mod_exp(privKey, @prime)
    puts("Our Public Key: #{publicKey.unpack1("H*")}")
    puts("Our Private-Key: #{privKey.unpack1("H*")}")
    publicBytes = publicKey.to_s(16) # Turn into Hex-String
    publicBytes = [publicBytes].pack("H*") # Pack into Raw Hex
    publicBytes = publicBytes.rjust(256, "\x00") # Pad to 256 bytes
    # Send over our Public Key.
    @socket.write(publicBytes)

    serverMsg = @socket.read(256);
    serverMsg.force_encoding("BINARY")
    serverKey = OpenSSL::BN.new(serverMsg, 2);
    puts("Their-Key: #{serverKey}")

    secret = serverKey.mod_exp(privKey, @prime);
    secret = secret.to_s(16);
    secret = [secret].pack("H*")

    @encryption_key = Digest::SHA256.digest(secret)

    puts(@encryption_key)
    puts "Secret: #{secret.unpack1("H*")}"
    puts "Handshake Complete. Key: #{@encryption_key.unpack1("H*")}"
  end

  def send_message(text)
    nonce_int = @send_nonce
    @send_nonce += 1

    # 12-byte Nonce (8-byte counter BE + 4-byte padding)
    nonce_bytes = [nonce_int].pack("Q>").rjust(12, "\x00")

    cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
    cipher.key = @encryption_key
    cipher.iv = nonce_bytes

    ciphertext = cipher.update(text) + cipher.final
    tag = cipher.auth_tag # 16 bytes

    payload = nonce_bytes + ciphertext + tag
    header = [payload.bytesize].pack("N")

    @socket.write(header + payload)
    puts "Sent encrypted message: #{text}"
  end

  def start_listener
    Thread.new do
      buffer = ""
      begin
        loop do
          # 1. Read from socket
          chunk = @socket.recv(4096).b
          if chunk.nil? || chunk.empty?
            puts "Server closed connection."
            break
          end
          buffer << chunk

          # 2. Process frames
          while buffer.bytesize >= 4
            length = buffer[0, 4].unpack1("N")

            # Length Safety Check
            if length > 500_000_000 || length == 0
              puts "Protocol Error: Invalid packet length (#{length})"
              @socket.close
              return
            end

            break if buffer.bytesize < (4 + length)

            # 3. Extract and Slice
            frame = buffer.slice!(0, 4 + length)
            nonce_bytes = frame[4, 12]
            payload     = frame[16..-1]
            ciphertext  = payload[0...-16]
            tag         = payload[-16..-1]

            # 4. Anti-Replay Check
            numeric_nonce = nonce_bytes.unpack1("H*").to_i(16)
            if numeric_nonce <= @highest_seen_nonce
              puts "Security Alert: Server Replay detected! Dropping connection."
              @socket.close
              return
            end
            @highest_seen_nonce = numeric_nonce

            # 5. Decrypt
            message = decrypt(nonce_bytes, ciphertext, tag)
            if message
              on_message(message)
            else
              puts "Security Alert: Could not verify server message integrity."
              @socket.close
              return
            end
          end
        end
      rescue => e
        puts "Listener Error: #{e.message}"
      ensure
        @socket.close unless @socket.closed?
      end
    end
  end

  def decrypt(nonce, ciphertext, tag)
    cipher = OpenSSL::Cipher.new("chacha20-poly1305").decrypt
    cipher.key = @encryption_key
    cipher.iv  = nonce
    cipher.auth_tag = tag
    begin
      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      nil
    end
  end

  # Override this or use a block to handle UI/logic
  def on_message(msg)
    puts "\n[Server]: #{msg}"
    print "> " # keep the prompt lookin' sharp
  end

end
class TunnelClient < SecureClient
  def initialize(remote_host, remote_port, local_proxy_port)
    super(remote_host, remote_port)
    @local_port = local_proxy_port
    @local_connections = {} # Store local sockets by an ID
    @write_mutex = Mutex.new
  end

  # We override the message handler to relay data to the local app
  def on_message(msg)
    # The message should ideally be prefixed with a connection_id 
    # but for a 1-to-1 tunnel, we just relay it to the current active local socket
    @active_local_socket.write(msg) if @active_local_socket && !@active_local_socket.closed?
  end

  def start_proxy
    proxy_server = TCPServer.new(@local_port)
    puts "Tunnel Entry Point ready on localhost:#{@local_port}"

    loop do
      # Accept connection from local app (e.g., a Browser or Telnet)
      local_socket = proxy_server.accept
      puts "Local app connected!"
      @active_local_socket = local_socket

      # Start reading from the local app and sending it INTO the tunnel
      Thread.new do
        begin
          while (data = local_socket.readpartial(4096))
            send_message(data)
          end
        rescue e
          puts "Local app disconnected."
        ensure
          local_socket.close rescue nil
        end
      end
    end
  end
end

# --- Main Execution ---

begin
  # 1. Connect to the Secure Server
  # 2. Open a local port (8082) for your apps to use
  client = TunnelClient.new("127.0.0.1", 8080, 8082)
  
  client.handshake
  client.start_listener # Background thread for server -> local traffic

  # Start the proxy (this blocks and waits for local connections)
  client.start_proxy

rescue => e
  puts "Tunnel Error: #{e.message}"
end