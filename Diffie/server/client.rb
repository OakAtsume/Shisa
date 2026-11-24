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
    @send_key = nil # client -> server (c2s)
    @recv_key = nil # server -> client (s2c)
    @send_nonce = 1 # deterministic; separate keys per direction make a random start unnecessary
    @highest_seen_nonce = 0
  end

  def handshake
    puts "Starting Handshake..."
    privKey = OpenSSL::BN.rand(256)
    publicKey = @gen.mod_exp(privKey, @prime)
    puts("Our Public Key: #{publicKey.to_s(16)}")
    puts("Our Private-Key: #{privKey.to_s(16)}")
    publicBytes = publicKey.to_s(16) # Turn into Hex-String
    publicBytes = "0#{publicBytes}" if publicBytes.bytesize.odd? # Guard odd-length: pack("H*") would append a trailing nibble and corrupt the key
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
    secret = "0#{secret}" if secret.bytesize.odd? # match the server's secret encoding
    secret = [secret].pack("H*")

    # Derive one key per direction from the shared secret (HKDF-SHA256).
    okm = OpenSSL::KDF.hkdf(secret, salt: "", info: "diffie/v1", length: 64, hash: "SHA256")
    @send_key = okm[0, 32]  # we are the client: send with c2s
    @recv_key = okm[32, 32] # receive with s2c

    puts "Secret: #{secret.unpack1("H*")}"
    puts "Handshake Complete. Send Key (c2s): #{@send_key.unpack1("H*")}"
    puts "Handshake Complete. Recv Key (s2c): #{@recv_key.unpack1("H*")}"
  end

  def send_message(text)
    nonce_int = @send_nonce
    @send_nonce += 1

    # 12-byte Nonce (8-byte counter BE + 4-byte padding)
    nonce_bytes = [nonce_int].pack("Q>").rjust(12, "\x00")

    cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
    cipher.key = @send_key
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
      buffer = "".b
      begin
        loop do
          # 1. Read from socket (recv returns "" on EOF, nil on a closed socket)
          chunk = @socket.recv(4096)
          if chunk.nil? || chunk.empty?
            puts "Server closed connection."
            break
          end
          buffer << chunk.b

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
    cipher.key = @recv_key
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

# # --- Execution ---
# begin
#   client = SecureClient.new("127.0.0.1", 8080)
#   client.handshake
#   client.send_message("Hello Secure World!")
#   client.send_message("This is a second packet with a new nonce.")

# rescue => e
#   puts "Client Error: #{e.message} #{e.backtrace.join("\n")}"
# end

# loop do
#   sleep 1
# end

begin
  client = SecureClient.new("127.0.0.1", 8081)
  client.handshake
  
  # Start the background listener
  client.start_listener

  # Now you can send messages while the listener waits for replies
  client.send_message("Hello Secure World!")
  
  # Simple REPL (Read-Eval-Print Loop)
  loop do
    print "> "
    input = gets.chomp
    break if input == "exit"
    client.send_message(input)
  end

rescue => e
  puts "Client Error: #{e.message}\n#{e.backtrace.join("\n")}"
end


# class AttackerClient < SecureClient
#   # Attack 1: Replay Attack
#   # We send a valid packet, then send the EXACT same bytes again.
#   def perform_replay_attack(text)
#     nonce_int = @send_nonce
#     @send_nonce += 1
    
#     # Standard encryption logic...
#     nonce_bytes = [nonce_int].pack("Q>").rjust(12, "\x00")
#     cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
#     cipher.key = @encryption_key
#     cipher.iv = nonce_bytes
#     ciphertext = cipher.update(text) + cipher.final
#     tag = cipher.auth_tag
    
#     packet = [nonce_bytes.bytesize + ciphertext.bytesize + tag.bytesize].pack("N") + 
#              nonce_bytes + ciphertext + tag

#     puts "--- Attacking: Sending Packet ---"
#     @socket.write(packet)
    
#     puts "--- Attacking: Replaying Same Packet ---"
#     sleep(1) # Ensure the server has time to process the first one
#     @socket.write(packet) 
#   end

#   # Attack 2: Bit-Flipping (Tampering)
#   # We encrypt a message, but change one single bit in the ciphertext.
#   # This should trigger the Poly1305 Tag Failure.
#   def perform_tamper_attack(text)
#     nonce_int = @send_nonce
#     @send_nonce += 1
#     nonce_bytes = [nonce_int].pack("Q>").rjust(12, "\x00")
    
#     cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
#     cipher.key = @encryption_key
#     cipher.iv = nonce_bytes
#     ciphertext = cipher.update(text) + cipher.final
    
#     # MALICE: Flip the last byte of the ciphertext
#     ciphertext[-1] = (ciphertext[-1].ord ^ 0xFF).chr 
    
#     tag = cipher.auth_tag
#     packet = [nonce_bytes.bytesize + ciphertext.bytesize + tag.bytesize].pack("N") + 
#              nonce_bytes + ciphertext + tag

#     puts "--- Attacking: Sending Tampered Ciphertext ---"
#     @socket.write(packet)
#   end

#   # Attack 3: Length Lie (The RAM Bomb)
#   # We send a header claiming the packet is 400MB, but send nothing else.
#   def perform_length_attack
#     puts "--- Attacking: Sending 400MB Length Claim ---"
#     fake_header = [400_000_000].pack("N")
#     @socket.write(fake_header)
#   end
# end

# # --- Run the Attacks ---
# begin
#   attacker = AttackerClient.new("127.0.0.1", 8080)
#   attacker.handshake
  
#   # Choose your weapon:
#   # attacker.perform_replay_attack("I am a normal message.")
#   # attacker.perform_tamper_attack("I am a secret message.")
#   attacker.perform_length_attack
  
# rescue => e
#   puts "Client stopped: #{e.message}"
# end
