require "base64"

# Client-side tunnel handler.
# Responds to tunnel_open by connecting to the target host:port and
# relaying data bidirectionally through the encrypted Diffie channel.
module TunnelHandler
  @@tunnels = {} of String => TCPSocket

  def self.register(client : ProtocolClient)
    # Server asks us to open a connection to a target.
    client.on("tunnel_open") do |env|
      conn_id = env.id
      next unless conn_id
      payload = env.payload
      next unless payload

      host = payload["host"].as_s
      port = payload["port"].as_i

      begin
        socket = TCPSocket.new(host, port, connect_timeout: 10.seconds)
        socket.tcp_nodelay = true
        @@tunnels[conn_id] = socket

        client.send(Envelope.new("tunnel_ready", conn_id))

        # Read from remote target and forward to server.
        spawn do
          begin
            buffer = Bytes.new(4096)
            loop do
              n = socket.read(buffer)
              break if n == 0

              b64 = Base64.strict_encode(buffer[0, n])
              data_payload = JSON.parse(
                JSON.build { |j| j.object { j.field "data", b64 } }
              )
              client.send(Envelope.new("tunnel_data", conn_id, data_payload))
            end
          rescue
          ensure
            if @@tunnels.delete(conn_id)
              client.send(Envelope.new("tunnel_close", conn_id))
            end
            socket.close rescue nil
          end
        end
      rescue ex
        error_payload = JSON.parse(
          JSON.build { |j| j.object { j.field "error", ex.message.to_s } }
        )
        client.send(Envelope.new("tunnel_error", conn_id, error_payload))
      end
    end

    # Incoming data from server's local socket → write to remote target.
    client.on("tunnel_data") do |env|
      conn_id = env.id
      next unless conn_id
      socket = @@tunnels[conn_id]?
      next unless socket

      b64 = env.payload.try(&.["data"]?.try(&.as_s))
      next unless b64

      begin
        socket.write(Base64.decode(b64))
      rescue
        @@tunnels.delete(conn_id)
        socket.close rescue nil
        client.send(Envelope.new("tunnel_close", conn_id))
      end
    end

    # Server closed its end of the tunnel.
    client.on("tunnel_close") do |env|
      conn_id = env.id
      next unless conn_id
      socket = @@tunnels.delete(conn_id)
      socket.try(&.close) rescue nil
    end

    # ── remote forwarding (-R): client listens, server connects locally ──

    client.on("rtunnel_listen") do |env|
      req_id = env.id
      next unless req_id
      payload = env.payload
      next unless payload

      remote_port = payload["port"].as_i
      listener_id = req_id

      begin
        tcp = TCPServer.new("0.0.0.0", remote_port)
        @@rlisteners[listener_id] = tcp

        client.send(Envelope.new("rtunnel_ready", listener_id))

        spawn do
          begin
            loop do
              sock = tcp.accept? rescue nil
              break unless sock
              conn_id = Random::Secure.hex(6)
              sock.tcp_nodelay = true
              @@tunnels[conn_id] = sock

              client.send(Envelope.new("rtunnel_accept", conn_id,
                JSON.parse(JSON.build { |j| j.object { j.field "listener", listener_id } })))

              spawn do
                begin
                  buffer = Bytes.new(4096)
                  loop do
                    n = sock.read(buffer)
                    break if n == 0
                    b64 = Base64.strict_encode(buffer[0, n])
                    client.send(Envelope.new("tunnel_data", conn_id,
                      JSON.parse(JSON.build { |j| j.object { j.field "data", b64 } })))
                  end
                rescue
                ensure
                  if @@tunnels.delete(conn_id)
                    client.send(Envelope.new("tunnel_close", conn_id))
                  end
                  sock.close rescue nil
                end
              end
            end
          rescue
          ensure
            @@rlisteners.delete(listener_id)
            tcp.close rescue nil
          end
        end
      rescue ex
        client.send(Envelope.new("rtunnel_error", listener_id,
          JSON.parse(JSON.build { |j| j.object { j.field "error", ex.message.to_s } })))
      end
    end

    client.on("rtunnel_stop") do |env|
      listener_id = env.id
      next unless listener_id
      tcp = @@rlisteners.delete(listener_id)
      tcp.try(&.close) rescue nil
    end
  end

  @@rlisteners = {} of String => TCPServer
end
