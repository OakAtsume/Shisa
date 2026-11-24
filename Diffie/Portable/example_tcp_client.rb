# A TCP client built on the transport-agnostic Diffie::Session — proof that the
# portable library drives a real socket and interops with ../server/main.rb.
#
#   ruby example_tcp_client.rb [host] [port]
#
# Type lines to send; "exit" (or Ctrl-D) quits. This is the Ruby analogue of the
# Crystal SecureClient: all crypto/framing lives in diffie.rb, this is plumbing.
require_relative "diffie"
require "socket"

class TCPClient
  def initialize(host, port)
    @host = host
    @port = port
    @session = Diffie::Session.new(:client)
    @write_mutex = Mutex.new
  end

  def connect
    @socket = TCPSocket.new(@host, @port)

    # Handshake: swap 256-byte public keys, then derive directional keys.
    @socket.write(@session.local_public_key)
    peer = @socket.read(Diffie::PUBKEY_BYTES)
    @session.complete_handshake(peer)
    puts "[+] handshake complete"
  end

  def send_message(text)
    @write_mutex.synchronize do
      @socket.write(Diffie::Framing.frame(@session.encrypt(text)))
    end
  end

  def start_reader(&on_message)
    Thread.new do
      parser = Diffie::FrameParser.new
      loop do
        chunk = @socket.recv(4096)
        break if chunk.nil? || chunk.empty?

        parser.feed(chunk) do |record|
          begin
            on_message.call(@session.decrypt(record))
          rescue Diffie::Error => e
            warn "[protocol-error] #{e.class}: #{e.message}"
          end
        end
      end
    rescue IOError, Errno::ECONNRESET
      # socket closed
    ensure
      puts "[-] disconnected"
    end
  end

  def close
    @socket&.close
  end
end

host = ARGV[0] || "127.0.0.1"
port = (ARGV[1] || "8081").to_i

client = TCPClient.new(host, port)
client.connect
client.start_reader { |msg| puts "[server] #{msg}" }

while (line = $stdin.gets)
  line = line.chomp
  next if line.empty?
  break if line == "exit"

  client.send_message(line)
end
client.close
