require "socket"
require "securerandom"
require "thread"
require "timeout"
require_relative("diffie")

class SocketServer
  HANDSHAKE_TIMEOUT = 10

  attr_reader :clients
  attr_accessor :identity_key, :authorized_client_keys

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

    @identity_key = nil
    @authorized_client_keys = []

    @server = TCPServer.new(port)
    puts("Server started on port TCP/IP(#{port})")
  end

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
    emit(:onDisconnect, client_id, client[:socket])
    @clients.delete(client_id)
  end

  def handleClient(client_id)
    client = @clients[client_id]
    socket = client[:socket]
    session = client[:session]

    parser = Diffie::FrameParser.new

    loop do
      break unless client[:alive]

      begin
        chunk = socket.recv(4096)
        if chunk.nil? || chunk.empty?
          disconnect(client_id)
          break
        end
      rescue => e
        break unless client[:alive]

        emit(:onProtocolError, client_id, socket, 3, "Generic TCP Error: #{e.message}")
        disconnect(client_id)
        break
      end

      begin
        parser.feed(chunk) do |record|
          message = session.decrypt(record)
          emit(:onMessage, client_id, socket, message)
        end
      rescue Diffie::ReplayError => e
        emit(:onProtocolError, client_id, socket, 0, "Possible Packet-Replay attack detected (#{e.message}). Connection has been blocked.")
        disconnect(client_id)
        return
      rescue Diffie::DecryptError => e
        emit(:onProtocolError, client_id, socket, 1, "Unable to decrypt message from host (#{e.message}). Potential broken client or tampering. Connection has been blocked.")
        disconnect(client_id)
        return
      rescue Diffie::Error => e
        emit(:onProtocolError, client_id, socket, 2, "Message Length was too Big/Small (#{e.message}).")
        disconnect(client_id)
        return
      end
    end

    if parser.pending_bytes > 0
      emit(:onProtocolError, client_id, socket, 2, "Connection closed with partial data in buffer (#{parser.pending_bytes} bytes).")
    end
  end

  def write(client_id, plaintext)
    client = @clients[client_id]
    return false unless client && client[:alive]

    client[:write_mutex].synchronize do
      return false unless client[:alive]
      return false unless client[:session].handshake_complete?

      frame = Diffie::Framing.frame(client[:session].encrypt(plaintext))
      begin
        client[:socket].write(frame)
        true
      rescue => e
        puts("Failed to Write to #{client_id}: #{e.message}")
        disconnect(client_id)
        false
      end
    end
  end

  def start()
    raise "Server identity key not set — call load_keys first" unless @identity_key

    loop do
      socket = @server.accept()

      clientId = SecureRandom.hex(8)
      session = Diffie::Session.new(:server)
      @clients[clientId] = {
        socket: socket,
        alive: true,
        write_mutex: Mutex.new(),
        host: [
          socket.peeraddr[3],
          socket.peeraddr[1],
        ],
        session: session,
      }
      host = "#{@clients[clientId][:host][0]}:#{@clients[clientId][:host][1]}"

      begin
        Timeout.timeout(HANDSHAKE_TIMEOUT) do
          # X25519 key exchange: swap 32-byte public keys
          socket.write(session.local_public_key)
          clientreply = socket.read(Diffie::PUBKEY_BYTES)
          if clientreply.nil?
            emit(:onHandshakeError, host, 0, "Connection Early dropped :shrug:")
            abortHandshake(clientId)
            next
          end
          if clientreply.bytesize < Diffie::PUBKEY_BYTES
            emit(:onHandshakeError, host, 1, "Message was less than #{Diffie::PUBKEY_BYTES} Bytes.")
            abortHandshake(clientId)
            next
          end

          session.complete_handshake(clientreply)

          # Mutual auth: send challenge, then verify response
          challenge = session.create_auth(@identity_key)
          socket.write(Diffie::Framing.frame(session.encrypt(challenge)))

          # Read the client's auth response (one framed+encrypted record)
          header = socket.read(Diffie::Framing::HEADER_SIZE)
          raise Diffie::HandshakeError, "auth response: connection dropped" unless header && header.bytesize == Diffie::Framing::HEADER_SIZE
          length = header.unpack1("N")
          raise Diffie::HandshakeError, "auth response: bad frame length" if length.zero? || length > Diffie::Framing::MAX_FRAME
          record = socket.read(length)
          raise Diffie::HandshakeError, "auth response: short read" unless record && record.bytesize == length

          response = session.decrypt(record)
          session.verify_auth(response, @authorized_client_keys)

          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)

          t = Thread.new { handleClient(clientId) }
          emit(:onConnect, clientId, socket)
          @threads << t
        end
      rescue Timeout::Error
        emit(:onHandshakeError, host, 2, "Handshake timed out after #{HANDSHAKE_TIMEOUT}s")
        abortHandshake(clientId)
        next
      rescue Diffie::AuthError => e
        emit(:onHandshakeError, host, 3, "Auth failed: #{e.message}")
        abortHandshake(clientId)
        next
      rescue Diffie::HandshakeError => e
        emit(:onHandshakeError, host, 2, e.message)
        abortHandshake(clientId)
        next
      rescue => e
        emit(:onHandshakeError, host, 2, "#{e}\n#{e.backtrace.join("\n")}")
        abortHandshake(clientId)
        next
      end
    end
  end

  private

  def abortHandshake(client_id)
    client = @clients.delete(client_id)
    return unless client

    client[:alive] = false
    client[:socket].close rescue nil
  end
end
