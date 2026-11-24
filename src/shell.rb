# frozen_string_literal: true

# Interactive shell for the Shisa control server.
# Provides client selection (use), filesystem commands, remote exec,
# file transfer, sysadmin/network tools, port forwarding, groups, and history.

require "securerandom"
require "digest"
require "tempfile"
require "fileutils"
require "base64"
require "timeout"
require "readline"
require_relative "storage"
require_relative "tunnel_server"

# Thread-safe request-reply synchronization.
class ReplyWaiter
  def initialize
    @pending = {}
    @mutex   = Mutex.new
  end

  def register(request_id)
    queue = Queue.new
    @mutex.synchronize { @pending[request_id] = queue }
    queue
  end

  def resolve(request_id, value)
    @mutex.synchronize { @pending[request_id]&.push(value) }
  end

  def unregister(request_id)
    @mutex.synchronize { @pending.delete(request_id) }
  end
end

class Shell
  CHUNK_SIZE = 65_536

  GLOBAL_COMMANDS = %w[
    use who list broadcast kick group alias note history script scp help quit exit
  ].freeze

  CLIENT_COMMANDS = %w[
    cd pwd ls cat edit exec download upload ps top reboot shutdown
    ifconfig netstat forward tunnels tunnel sessions shell memfile
    cron journal restart migrate daemonize kill-daemon escalate
    service watch find pkg script scp route
    who info back help quit exit
  ].freeze

  def initialize(server)
    @server     = server
    @waiter     = ReplyWaiter.new
    @storage    = ServerStorage.new
    @tunnel_mgr = TunnelManager.new(server)
    @target     = nil       # client ID
    @group      = nil       # group name (mutually exclusive with @target)
    @listen_sessions = {}   # listen_id => { client_id:, tty: }
    @shell_active = nil     # shell session id when in interactive shell mode
    @shell_closed = false   # set true when remote shell exits
    @recording = false
    @recording_name = nil
    @recording_commands = []
    register_reply_handlers
    setup_readline
  end

  def run
    puts help_text
    catch(:quit) do
      loop do
        begin
          $current_prompt = prompt_string
          $current_prompt = "\e[31m[REC:#{@recording_name}]\e[0m #{$current_prompt}" if @recording
          line = Readline.readline($current_prompt, false)
          break if line.nil?
          line = line.strip
          next if line.empty?

          Readline::HISTORY.push(line)
          @storage.add_history(line, target: @target || (@group && "@#{@group}"))

          cmd, rest = line.split(" ", 2)

          @recording_commands << line if @recording && cmd.downcase != "script"

          if @target || @group
            dispatch_client(cmd, rest)
          else
            dispatch_global(cmd, rest)
          end
        rescue Interrupt
          puts
          next
        rescue => e
          say "error: #{e.message}"
        end
      end
    end
    cleanup
  end

  def handle_reply(env)
    @waiter.resolve(env.id, env) if env.id
  end

  # Called when a client disconnects so tunnels are cleaned up.
  def on_client_disconnect(client_id)
    @tunnel_mgr.close_client_tunnels(client_id)
    removed = @listen_sessions.select { |_id, info| info[:client_id] == client_id }
    removed.each_key { |id| @listen_sessions.delete(id) }
  end

  def handle_session_data(env)
    listen_id = env.id.to_s
    return unless @listen_sessions.key?(listen_id)

    b64 = env.payload&.dig(:data)&.to_s
    return unless b64 && !b64.empty?

    data = Base64.decode64(b64)
    print data
  end

  def handle_shell_output(env)
    return unless @shell_active == env.id
    b64 = env.payload&.dig(:data)&.to_s
    return unless b64 && !b64.empty?
    print Base64.decode64(b64)
  end

  def handle_shell_closed(env)
    if @shell_active == env.id
      @shell_closed = true
    end
  end

  def setup_readline
    shell = self
    Readline.completion_proc = proc do |input|
      candidates = if shell.instance_variable_get(:@target) || shell.instance_variable_get(:@group)
        CLIENT_COMMANDS
      else
        GLOBAL_COMMANDS
      end

      if input.include?(" ")
        nil
      else
        matches = candidates.select { |c| c.start_with?(input.downcase) }
        # Also complete client IDs / aliases / group names for 'use'
        buf = Readline.line_buffer rescue input
        if buf&.start_with?("use ")
          ids = shell.send(:completable_ids)
          matches = ids.select { |c| c.start_with?(input) }
        end
        matches.empty? ? nil : matches
      end
    end
    Readline.completion_append_character = " "
  end

  private

  def completable_ids
    ids = []
    @server.clients.each do |sid, c|
      info = c[:sysinfo] || {}
      hwid = (info[:hwid] || info["hwid"])&.to_s
      hostname = (info[:hostname] || info["hostname"])&.to_s
      ids << hwid if hwid && !hwid.empty?
      ids << hostname if hostname && !hostname.empty?
    end
    @storage.all_aliases.each { |a, _| ids << a }
    @storage.all_groups.each { |g, _| ids << "@#{g}" }
    ids.uniq
  end

  # ── prompt ──────────────────────────────────────────────────────────────

  def prompt_string
    if @group
      members = alive_group_members
      "\e[35m[@#{@group} (#{members.size})]\e[0m> "
    elsif @target
      sid = socket_for_hwid(@target)
      label = if sid
        hostname = @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
        hostname && !hostname.empty? ? hostname : @target[0, 12]
      else
        @target[0, 12]
      end
      "\e[36m[#{label}]\e[0m> "
    else
      "\e[33mshisa\e[0m> "
    end
  end

  # ── HWID helpers ────────────────────────────────────────────────────────

  def hwid_of(socket_id)
    c = @server.clients[socket_id]
    return nil unless c
    info = c[:sysinfo]
    return nil unless info
    (info[:hwid] || info["hwid"])&.to_s
  end

  def socket_for_hwid(hwid)
    return nil unless hwid
    @server.clients.each do |sid, _|
      return sid if hwid_of(sid) == hwid
    end
    nil
  end

  # ── target helpers ──────────────────────────────────────────────────────

  def target_ids
    if @group
      alive_group_members
    elsif @target
      sid = socket_for_hwid(@target)
      sid ? [sid] : []
    else
      []
    end
  end

  def alive_group_members
    @storage.group_members(@group).filter_map { |hwid| socket_for_hwid(hwid) }
  end

  def multi_target?
    @group != nil
  end

  # Send to all targets in parallel and collect results.
  def parallel_request(event, payload = nil, timeout: 30)
    ids = target_ids
    results = {}
    threads = ids.map do |cid|
      Thread.new do
        reply = request(cid, event, payload, timeout: timeout)
        results[cid] = reply
      end
    end
    threads.each(&:join)
    results
  end

  # Print results from a parallel request with client-id prefixes.
  def print_multi(results, &block)
    results.each do |cid, reply|
      prefix = "\e[90m[#{cid[0,8]}]\e[0m "
      if reply
        lines = block.call(reply)
        lines.each { |l| puts "#{prefix}#{l}" } if lines
      else
        puts "#{prefix}\e[31mtimeout\e[0m"
      end
    end
  end

  # ── dispatch ────────────────────────────────────────────────────────────

  def dispatch_global(cmd, rest)
    case cmd.downcase
    when "use", "u"         then cmd_use(rest)
    when "who", "list"      then cmd_who
    when "broadcast", "bc"  then cmd_broadcast(rest)
    when "kick"             then cmd_kick(rest)
    when "group", "g"       then cmd_group(rest)
    when "alias"            then cmd_alias(rest)
    when "note", "notes"    then cmd_note(rest)
    when "history"          then cmd_history(rest)
    when "script"           then cmd_script(rest)
    when "scp"              then cmd_scp(rest)
    when "help", "h", "?"   then puts help_text
    when "refresh"          then cmd_refresh
    when "clear"            then printf("\033[2J\033[H")
    when "quit", "exit", "q" then throw :quit
    else say "unknown command '#{cmd}' — type 'help'"
    end
  end

  def dispatch_client(cmd, rest)
    if @target && !socket_for_hwid(@target)
      say "client #{@target[0,12]} disconnected"
      @target = nil
      return
    end

    case cmd.downcase
    # filesystem
    when "cd"                then require_single!(:cd) && cmd_cd(rest)
    when "pwd"               then cmd_pwd
    when "ls", "dir"         then cmd_ls(rest)
    when "cat", "type"       then require_single!(:cat) && cmd_cat(rest)
    when "edit"              then require_single!(:edit) && cmd_edit(rest)
    when "exec", "run", "!"  then cmd_exec(rest)
    when "download", "dl"    then require_single!(:download) && cmd_download(rest)
    when "upload", "ul"      then require_single!(:upload) && cmd_upload(rest)
    when "mkdir"             then cmd_mkdir(rest)
    when "rm"                then cmd_rm(rest)
    when "mv"                then cmd_mv(rest)
    when "cp"                then cmd_cp(rest)
    when "chmod"             then cmd_chmod(rest)
    # sysadmin
    when "ps"                then cmd_ps(rest)
    when "top"               then cmd_top
    when "df"                then cmd_df
    when "free"              then cmd_free
    when "du"                then cmd_du(rest)
    when "reboot"            then cmd_reboot
    when "shutdown"          then cmd_shutdown
    # network
    when "ifconfig", "ip"    then cmd_ifconfig
    when "netstat", "ss"     then cmd_netstat(rest)
    # tunnels
    when "forward", "fwd"    then require_single!(:forward) && cmd_forward(rest)
    when "tunnels"           then cmd_tunnels
    when "tunnel"            then cmd_tunnel(rest)
    # sessions
    when "sessions", "session" then cmd_sessions(rest)
    # interactive shell
    when "shell"             then require_single!(:shell) && cmd_shell
    # memfile
    when "memfile", "mf"     then require_single!(:memfile) && cmd_memfile(rest)
    # cron
    when "cron"              then cmd_cron(rest)
    # journal / syslog
    when "journal", "log", "syslog" then cmd_journal(rest)
    # daemon control
    when "restart"           then cmd_restart
    when "migrate"           then cmd_migrate(rest)
    when "daemonize"         then cmd_daemonize(rest)
    when "kill-daemon"       then cmd_kill_daemon
    when "escalate"          then require_single!(:escalate) && cmd_escalate(rest)
    # systemd services
    when "service", "svc"    then cmd_service(rest)
    when "systemctl"         then cmd_service(rest)
    # watch / find / pkg
    when "watch"             then require_single!(:watch) && cmd_watch(rest)
    when "find"              then cmd_find(rest)
    when "pkg", "apt", "dnf", "pacman" then cmd_pkg(rest)
    when "route"             then require_single!(:route) && cmd_route(rest)
    when "update"            then require_single!(:update) && cmd_update(rest)
    # script / scp
    when "script"            then cmd_script(rest)
    when "scp"               then cmd_scp(rest)
    # meta
    when "who"               then cmd_who
    when "info"              then cmd_info
    when "back", "deselect"  then @target = nil; @group = nil
    when "help", "h", "?"    then puts client_help_text
    when "quit", "exit", "q" then throw :quit
    else say "unknown command '#{cmd}' — type 'help'"
    end
  end

  def require_single!(cmd)
    if multi_target?
      say "#{cmd} requires a single client (use <id>)"
      false
    else
      true
    end
  end

  # ── global commands ─────────────────────────────────────────────────────

  def cmd_use(rest)
    id = rest&.strip
    if id.nil? || id.empty?
      say "usage: use <id|alias|hostname|@group>"
      return
    end

    # Group targeting
    if id.start_with?("@")
      gname = id[1..]
      unless @storage.group_names.include?(gname)
        say "no group '#{gname}'"
        return
      end
      members = @storage.group_members(gname).select { |hwid| socket_for_hwid(hwid) }
      if members.empty?
        say "group '#{gname}' has no online members"
        return
      end
      @target = nil
      @group  = gname
      say "targeting group \e[1m@#{gname}\e[0m (#{members.size} online)"
      return
    end

    hwid = resolve(id)
    return unless hwid
    @group  = nil
    @target = hwid

    sid = socket_for_hwid(hwid)
    hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
    label = hostname && !hostname.empty? ? "#{hwid[0,12]} (#{hostname})" : hwid[0,12]
    say "selected \e[1m#{label}\e[0m"
  end

  def cmd_who
    clients = @server.clients.to_a
    if clients.empty?
      say "no clients connected"
      return
    end
    fmt = "  %1s %-12s %-20s %-12s %-10s %-18s %-8s %s"
    puts format(fmt, "", "HWID", "HOST", "HOSTNAME", "USER", "OS", "PING", "UPTIME")
    puts "  " + "-" * 100
    clients.each do |sid, c|
      host  = "#{c[:host][0]}:#{c[:host][1]}"
      info  = c[:sysinfo] || {}
      hwid  = (info[:hwid] || info["hwid"] || "-").to_s
      hname = (info[:hostname] || info["hostname"] || "-").to_s
      os    = (info[:os_name]  || info["os_name"]  || "-").to_s
      user  = (info[:sudo_user] || info["sudo_user"])&.to_s
      user  = nil if user == "unknown" || user.nil? || user.empty?
      user ||= "root" if (info[:pid] || info["pid"])&.to_s == "1"
      user ||= "-"
      marker = (@target && hwid == @target) ? "*" : " "

      lat = c[:latency_ms]
      ping_str = lat ? "#{lat}ms" : "-"
      ping_color = if lat.nil? then ""
        elsif lat < 50 then "\e[32m"
        elsif lat < 150 then "\e[33m"
        else "\e[31m"
        end
      ping_str = "#{ping_color}#{ping_str}\e[0m" unless ping_color.empty?

      uptime_str = if c[:connected_at]
        fmt_uptime((Time.now - c[:connected_at]).to_i)
      else
        "-"
      end

      puts format(fmt, marker, hwid[0,12], host, hname[0,12], user[0,10], os[0,18], ping_str, uptime_str)
      ali = @storage.alias_for(hwid)
      note = @storage.get_note(hwid)
      extra = [ali ? "alias:#{ali}" : nil, note].compact
      puts "    \e[90m#{extra.join(" | ")}\e[0m" unless extra.empty?
    end
    puts
    say "#{clients.size} client(s) connected"
  end

  def cmd_broadcast(rest)
    if rest.nil? || rest.empty?
      say "usage: broadcast <message>"
      return
    end
    sent = @server.broadcast_event("message", { text: rest })
    say "sent to #{sent}/#{@server.clients.size} clients"
  end

  def cmd_kick(rest)
    id = rest&.strip
    hwid = id && resolve(id)
    return unless hwid
    sid = socket_for_hwid(hwid)
    return say("#{hwid[0,12]} is not connected") unless sid
    @target = nil if @target == hwid
    @server.disconnect(sid)
    say "kicked #{hwid[0,12]}"
  end

  # ── refresh authorized keys ──────────────────────────────────────────────

  def cmd_refresh
    keys_dir = File.join(File.dirname(__FILE__), "..", "keys", "authorized_clients")
    files = Dir.glob(File.join(keys_dir, "*.pub"))
    keys = files.map { |f| [File.read(f).strip].pack("H*").b }
    @server.transport.authorized_client_keys = keys
    say "reloaded #{keys.size} authorized client key#{keys.size == 1 ? '' : 's'} from keys/authorized_clients/"
  end

  # ── groups ──────────────────────────────────────────────────────────────

  def cmd_group(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "create", "new"
      name = args&.strip
      return say("usage: group create <name>") unless name && !name.empty?
      @storage.create_group(name)
      say "created group '#{name}'"

    when "delete", "rm"
      name = args&.strip
      return say("usage: group delete <name>") unless name && !name.empty?
      @storage.delete_group(name)
      say "deleted group '#{name}'"

    when "add"
      parts = args&.split(" ", 2)
      return say("usage: group add <name> <id>") unless parts && parts.size == 2
      gname, cid = parts
      hwid = resolve(cid)
      return unless hwid
      @storage.add_to_group(gname, hwid)
      say "added #{hwid[0,12]} to '#{gname}'"

    when "remove", "rem"
      parts = args&.split(" ", 2)
      return say("usage: group remove <name> <id>") unless parts && parts.size == 2
      gname, id = parts
      hwid = @storage.resolve_alias(id) || id
      @storage.remove_from_group(gname, hwid)
      say "removed from '#{gname}'"

    when "list", "ls", nil
      groups = @storage.groups
      if groups.empty?
        say "no groups defined"
      else
        groups.each do |name, members|
          online = members.count { |hwid| socket_for_hwid(hwid) }
          puts "  \e[1m@#{name}\e[0m  #{members.size} members (#{online} online)"
          members.each do |hwid|
            sid = socket_for_hwid(hwid)
            status = sid ? "\e[32monline\e[0m" : "\e[90moffline\e[0m"
            hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
            label = hostname && !hostname.empty? ? "#{hwid[0,12]} (#{hostname})" : hwid[0,12]
            puts "    #{label}  #{status}"
          end
        end
      end

    when "show"
      gname = args&.strip
      return say("usage: group show <name>") unless gname
      members = @storage.group_members(gname)
      if members.empty?
        say "group '#{gname}' is empty or doesn't exist"
      else
        members.each do |hwid|
          sid = socket_for_hwid(hwid)
          status = sid ? "\e[32monline\e[0m" : "\e[90moffline\e[0m"
          hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
          label = hostname && !hostname.empty? ? "#{hwid[0,12]} (#{hostname})" : hwid[0,12]
          puts "  #{label}  #{status}"
        end
      end

    else
      puts <<~TXT
        group create <name>            create a group
        group delete <name>            delete a group
        group add <name> <id>          add client to group (by HWID/alias/hostname)
        group remove <name> <id>       remove client from group
        group list                     list all groups
        group show <name>              show group members
      TXT
    end
  end

  # ── history ─────────────────────────────────────────────────────────────

  def cmd_history(rest)
    n = (rest&.strip&.to_i rescue 20) || 20
    n = [n, 1].max
    entries = @storage.recent_history(n)
    if entries.empty?
      say "no history"
      return
    end
    entries.each_with_index do |e, i|
      target = e["target"] ? " \e[36m#{e["target"].to_s[0,10]}\e[0m" : ""
      puts format("  \e[90m%-20s\e[0m%s  %s", e["time"], target, e["command"])
    end
  end

  # ── aliases ─────────────────────────────────────────────────────────────

  def cmd_alias(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "set"
      parts = args&.split(" ", 2)
      return say("usage: alias set <name> <id>") unless parts && parts.size == 2
      name, cid = parts
      hwid = resolve(cid)
      return unless hwid
      @storage.set_alias(name, hwid)
      say "alias '#{name}' -> #{hwid[0,12]}"

    when "remove", "rm"
      name = args&.strip
      return say("usage: alias remove <name>") unless name
      @storage.remove_alias(name)
      say "removed alias '#{name}'"

    when "list", "ls", nil
      aliases = @storage.all_aliases
      if aliases.empty?
        say "no aliases"
      else
        aliases.each do |name, hwid|
          sid = socket_for_hwid(hwid)
          status = sid ? "\e[32monline\e[0m" : "\e[90moffline\e[0m"
          hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
          label = hostname && !hostname.empty? ? "#{hwid[0,12]} (#{hostname})" : hwid[0,12]
          puts "  \e[1m#{name}\e[0m -> #{label}  #{status}"
        end
      end

    else
      puts <<~TXT
        alias set <name> <id>          create an alias (by HWID/hostname)
        alias remove <name>            remove an alias
        alias list                     list all aliases
      TXT
    end
  end

  # ── notes ────────────────────────────────────────────────────────────────

  def cmd_note(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "set"
      parts = args&.split(" ", 2)
      return say("usage: note set <id|alias|hostname> <text>") unless parts && parts.size == 2
      id, text = parts
      hwid = resolve(id)
      return unless hwid
      @storage.set_note(hwid, text)
      say "note set for #{hwid[0,12]}"

    when "remove", "rm", "clear"
      id = args&.strip
      return say("usage: note remove <id>") unless id && !id.empty?
      hwid = resolve(id)
      return unless hwid
      @storage.remove_note(hwid)
      say "note removed for #{hwid[0,12]}"

    when "list", "ls", nil
      notes = @storage.all_notes
      if notes.empty?
        say "no notes"
      else
        notes.each do |hwid, text|
          sid = socket_for_hwid(hwid)
          status = sid ? "\e[32monline\e[0m" : "\e[90moffline\e[0m"
          hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
          label = hostname && !hostname.empty? ? "#{hwid[0,12]} (#{hostname})" : hwid[0,12]
          puts "  \e[1m#{label}\e[0m  #{status}"
          puts "    #{text}"
        end
      end

    else
      puts <<~TXT
        note set <id> <text>       set a note (by HWID/alias/hostname)
        note remove <id>           remove a note
        note list                  list all notes
      TXT
    end
  end

  # ── client: filesystem ──────────────────────────────────────────────────

  def cmd_cd(rest)
    path = rest&.strip
    return say("usage: cd <path>") if path.nil? || path.empty?
    reply = request(target_ids.first, "fs_cd", { path: path })
    return unless reply
    p = reply.payload
    return unless p
    p[:error] ? say("cd: #{p[:error]}") : say(p[:cwd].to_s)
  end

  def cmd_pwd
    if multi_target?
      print_multi(parallel_request("fs_pwd")) { |r| [r.payload&.dig(:cwd).to_s] }
    else
      reply = request(target_ids.first, "fs_pwd")
      say reply.payload[:cwd].to_s if reply&.payload
    end
  end

  def cmd_ls(rest)
    path = rest&.strip
    cmd = "ls -lhA --color=never"
    cmd += " #{shell_escape(path)}" if path && !path.empty?
    reply = request(target_ids.first, "exec", { cmd: cmd }, timeout: 10)
    return unless reply
    p = reply.payload
    return unless p
    if p[:exit_code].to_i != 0
      say "ls: #{(p[:stderr] || p[:stdout]).to_s.strip}"
    else
      puts p[:stdout].to_s
    end
  end

  def cmd_cat(rest)
    path = rest&.strip
    return say("usage: cat <path>") if path.nil? || path.empty?
    reply = request(target_ids.first, "fs_cat", { path: path })
    return unless reply
    p = reply.payload
    return unless p
    p[:error] ? say("cat: #{p[:error]}") : puts(p[:content].to_s)
  end

  def cmd_exec(rest)
    return say("usage: exec <command>") if rest.nil? || rest.empty?

    if multi_target?
      print_multi(parallel_request("exec", { cmd: rest }, timeout: 120)) do |r|
        p = r.payload
        next nil unless p
        lines = []
        out = p[:stdout]&.to_s; lines << out if out && !out.empty?
        err = p[:stderr]&.to_s; lines << "\e[31m#{err}\e[0m" if err && !err.empty?
        code = p[:exit_code]; lines << "\e[33m[exit #{code}]\e[0m" if code && code != 0
        lines.empty? ? ["(no output)"] : lines
      end
    else
      reply = request(target_ids.first, "exec", { cmd: rest }, timeout: 120)
      return unless reply
      p = reply.payload
      return unless p
      out = p[:stdout]&.to_s
      err = p[:stderr]&.to_s
      puts out if out && !out.empty?
      $stderr.puts "\e[31m#{err}\e[0m" if err && !err.empty?
      code = p[:exit_code]
      say "\e[33m[exit #{code}]\e[0m" if code && code != 0
    end
  end

  def cmd_info
    ids = target_ids
    ids.each do |sid|
      c = @server.clients[sid]
      next unless c
      hwid = hwid_of(sid)
      puts "\e[1m#{hwid || sid}\e[0m" if ids.size > 1
      info = c[:sysinfo] || {}
      if info.empty?
        say "  no system info"
      else
        info.each { |k, v| puts format("  \e[1m%-18s\e[0m %s", k, v) }
      end
      note = hwid && @storage.get_note(hwid)
      puts format("  \e[1m%-18s\e[0m %s", "note", note) if note
      puts if ids.size > 1
    end
  end

  # ── client: edit ────────────────────────────────────────────────────────

  def cmd_edit(rest)
    path = rest&.strip
    return say("usage: edit <remote-path>") if path.nil? || path.empty?

    tmpfile = Tempfile.new(["shisa_edit_", File.extname(path)])
    begin
      say "downloading #{path}..."
      sid = target_ids.first
      result = transfer_download(sid, path, tmpfile.path)
      unless result[:success]
        say "download failed: #{result[:error]}"
        return
      end
      editor = ENV["EDITOR"] || ENV["VISUAL"] || "nano"
      system(editor, tmpfile.path)
      say "uploading changes..."
      result = transfer_upload(sid, tmpfile.path, path)
      if result[:success]
        say "saved #{path} (#{fmt_bytes(result[:size])})"
      else
        say "upload failed: #{result[:error]}"
      end
    ensure
      tmpfile.close
      tmpfile.unlink
    end
  end

  # ── client: filesystem management ──────────────────────────────────────

  def cmd_mkdir(rest)
    path = rest&.strip
    return say("usage: mkdir <path>") if path.nil? || path.empty?
    reply = request(target_ids.first, "exec", { cmd: "mkdir -p #{shell_escape(path)} && echo OK" }, timeout: 10)
    return unless reply
    p = reply.payload
    p&.dig(:exit_code).to_i == 0 ? say("created #{path}") : say("mkdir: #{(p[:stderr] || p[:stdout]).to_s.strip}")
  end

  def cmd_rm(rest)
    args = rest&.strip
    return say("usage: rm <path> [-r] [-f]") if args.nil? || args.empty?

    flags = []
    paths = []
    args.split.each do |a|
      case a
      when "-r", "-rf", "-fr", "--recursive" then flags << "-r"
      when "-f", "--force" then flags << "-f"
      when "-d", "--dir" then flags << "-d"
      else paths << a
      end
    end

    return say("rm: no path specified") if paths.empty?
    target_desc = paths.join(", ")

    if flags.include?("-r")
      print "  \e[31m[!] Recursively delete #{target_desc}? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"
    end

    flag_str = flags.uniq.join(" ")
    cmd = "rm #{flag_str} #{paths.map { |p| shell_escape(p) }.join(' ')} 2>&1 && echo OK"
    reply = request(target_ids.first, "exec", { cmd: cmd }, timeout: 15)
    return unless reply
    p = reply.payload
    out = (p[:stdout] || p[:stderr]).to_s.strip
    out.include?("OK") ? say("removed #{target_desc}") : say("rm: #{out}")
  end

  def cmd_mv(rest)
    parts = rest&.split(" ", 2)
    return say("usage: mv <source> <dest>") unless parts && parts.size == 2
    src, dst = parts.map(&:strip)
    reply = request(target_ids.first, "exec", { cmd: "mv #{shell_escape(src)} #{shell_escape(dst)} 2>&1 && echo OK" }, timeout: 15)
    return unless reply
    p = reply.payload
    out = (p[:stdout] || p[:stderr]).to_s.strip
    out.include?("OK") ? say("moved #{src} -> #{dst}") : say("mv: #{out}")
  end

  def cmd_cp(rest)
    args = rest&.strip
    return say("usage: cp [-r] <source> <dest>") if args.nil? || args.empty?
    tokens = args.split
    flags = tokens.select { |t| t.start_with?("-") }.join(" ")
    paths = tokens.reject { |t| t.start_with?("-") }
    return say("usage: cp [-r] <source> <dest>") unless paths.size == 2
    reply = request(target_ids.first, "exec", { cmd: "cp #{flags} #{shell_escape(paths[0])} #{shell_escape(paths[1])} 2>&1 && echo OK" }, timeout: 15)
    return unless reply
    p = reply.payload
    out = (p[:stdout] || p[:stderr]).to_s.strip
    out.include?("OK") ? say("copied #{paths[0]} -> #{paths[1]}") : say("cp: #{out}")
  end

  def cmd_chmod(rest)
    parts = rest&.split(" ", 2)
    return say("usage: chmod <mode> <path>") unless parts && parts.size == 2
    mode, path = parts.map(&:strip)
    reply = request(target_ids.first, "exec", { cmd: "chmod #{shell_escape(mode)} #{shell_escape(path)} 2>&1 && echo OK" }, timeout: 10)
    return unless reply
    p = reply.payload
    out = (p[:stdout] || p[:stderr]).to_s.strip
    out.include?("OK") ? say("chmod #{mode} #{path}") : say("chmod: #{out}")
  end

  # ── client: disk / memory info ─────────────────────────────────────────

  def cmd_df
    reply = request(target_ids.first, "exec", { cmd: "df -h --output=target,fstype,size,used,avail,pcent 2>/dev/null || df -h" }, timeout: 10)
    return unless reply
    p = reply.payload
    return say("df: #{p[:error] || p[:stderr]}") if p&.dig(:error) || (p&.dig(:exit_code).to_i != 0 && p[:stderr] && !p[:stderr].to_s.empty?)
    puts p[:stdout].to_s
  end

  def cmd_free
    reply = request(target_ids.first, "exec", { cmd: "free -h 2>/dev/null || { echo 'Mem:'; head -5 /proc/meminfo; }" }, timeout: 10)
    return unless reply
    p = reply.payload
    puts p[:stdout].to_s
  end

  def cmd_du(rest)
    path = rest&.strip
    path = "." if path.nil? || path.empty?
    reply = request(target_ids.first, "exec", { cmd: "du -sh #{shell_escape(path)} 2>&1" }, timeout: 30)
    return unless reply
    p = reply.payload
    puts p[:stdout].to_s
  end

  # ── client: transfer ───────────────────────────────────────────────────

  def cmd_download(rest)
    parts = rest&.split(" ", 2)
    return say("usage: download <remote-path> <local-path>") unless parts && parts.size >= 2
    remote_path, local_path = parts

    reply = request(target_ids.first, "exec", { cmd: "if [ -d #{shell_escape(remote_path)} ]; then echo DIR; elif ls -d #{shell_escape(remote_path)} 2>/dev/null | wc -l | tr -d ' '; then true; fi" }, timeout: 10)
    if reply
      out = reply.payload[:stdout].to_s.strip
      if out.start_with?("DIR")
        return download_directory(target_ids.first, remote_path, local_path)
      end
      count = out.lines.last&.strip.to_i rescue 0
      if count > 1
        return download_glob(target_ids.first, remote_path, local_path)
      end
    end

    say "downloading #{remote_path}..."
    result = transfer_download(target_ids.first, remote_path, local_path)
    result[:success] ? say("downloaded #{fmt_bytes(result[:size])} -> #{local_path}") : say("failed: #{result[:error]}")
  end

  def cmd_upload(rest)
    parts = rest&.split(" ", 2)
    return say("usage: upload <local-path> <remote-path>") unless parts && parts.size >= 2
    local_path, remote_path = parts

    local_files = Dir.glob(local_path)
    if local_files.empty?
      return say("no files matching: #{local_path}")
    elsif local_files.size == 1 && File.file?(local_files.first)
      say "uploading #{local_files.first}..."
      result = transfer_upload(target_ids.first, local_files.first, remote_path)
      return result[:success] ? say("uploaded #{fmt_bytes(result[:size])} -> #{remote_path}") : say("failed: #{result[:error]}")
    end

    files = local_files.select { |f| File.file?(f) }
    if files.empty?
      if local_files.size == 1 && File.directory?(local_files.first)
        files = Dir.glob(File.join(local_files.first, "**", "*")).select { |f| File.file?(f) }
        base = local_files.first
      else
        return say("no regular files found")
      end
    else
      base = File.dirname(local_path.sub(/\*.*/, ""))
    end

    say "uploading #{files.size} file(s)..."
    ok = 0
    fail_count = 0
    files.each_with_index do |f, i|
      rel = f.sub(%r{^#{Regexp.escape(base)}/?}, "")
      dest = File.join(remote_path, rel)
      dir = File.dirname(dest)
      request(target_ids.first, "exec", { cmd: "mkdir -p #{shell_escape(dir)}" }, timeout: 5) if dir != "." && dir != remote_path
      print "\r  [#{i + 1}/#{files.size}] #{rel}"
      result = transfer_upload(target_ids.first, f, dest)
      result[:success] ? ok += 1 : fail_count += 1
    end
    puts
    say "uploaded #{ok}/#{files.size} file(s) -> #{remote_path}#{fail_count > 0 ? " (#{fail_count} failed)" : ""}"
  end

  # ── client: update (push local binary to client) ───────────────────────

  def cmd_update(rest)
    local_file = rest&.strip
    return say("usage: update <local-file>  — push a file to the client's install path") if local_file.nil? || local_file.empty?
    return say("local file not found: #{local_file}") unless File.exist?(local_file)

    sid = target_ids.first
    reply = request(sid, "exec", { cmd: "readlink -f /proc/self/exe 2>/dev/null || echo $0" }, timeout: 5)
    return say("couldn't determine client install path") unless reply
    remote_path = reply.payload[:stdout].to_s.strip
    return say("couldn't determine client install path") if remote_path.empty?

    say "pushing #{local_file} -> #{remote_path} (#{fmt_bytes(File.size(local_file))})"
    print "  \e[33mThis will overwrite the running binary. Continue? [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"

    result = transfer_upload(sid, local_file, remote_path)
    if result[:success]
      request(sid, "exec", { cmd: "chmod +x #{shell_escape(remote_path)}" }, timeout: 5)
      say "updated #{remote_path} (#{fmt_bytes(result[:size])}). Client must be restarted to use the new version."
    else
      say "update failed: #{result[:error]}"
    end
  end

  # ── client: sysadmin ───────────────────────────────────────────────────

  def cmd_ps(rest)
    filter = rest&.strip
    payload = filter && !filter.empty? ? { filter: filter } : nil

    if multi_target?
      print_multi(parallel_request("sys_ps", payload, timeout: 15)) do |r|
        p = r.payload
        next ["error: #{p[:error]}"] if p&.dig(:error)
        procs = p&.dig(:processes)
        next ["(no data)"] unless procs
        lines = [format("%-12s %7s %5s %5s %9s  %s", "USER", "PID", "%CPU", "%MEM", "RSS", "COMMAND")]
        procs.each do |pr|
          lines << format("%-12s %7s %5s %5s %9s  %s",
            pr[:user].to_s[0,12], pr[:pid], pr[:cpu], pr[:mem],
            fmt_bytes((pr[:rss].to_i rescue 0) * 1024), pr[:command].to_s[0,50])
        end
        lines
      end
    else
      reply = request(target_ids.first, "sys_ps", payload, timeout: 15)
      return unless reply
      p = reply.payload
      return say("ps: #{p[:error]}") if p&.dig(:error)
      procs = p&.dig(:processes)
      return unless procs
      fmt = "  %-12s %7s %5s %5s %9s  %s"
      lines = []
      lines << format(fmt, "USER", "PID", "%CPU", "%MEM", "RSS", "COMMAND")
      lines << "  " + "-" * 72
      procs.each do |pr|
        lines << format(fmt, pr[:user].to_s[0,12], pr[:pid], pr[:cpu], pr[:mem],
          fmt_bytes((pr[:rss].to_i rescue 0) * 1024), pr[:command].to_s[0,50])
      end
      paged(lines)
    end
  end

  def cmd_top
    ids = target_ids
    ids.each do |cid|
      reply = request(cid, "sys_top", nil, timeout: 10)
      unless reply
        puts "\e[90m[#{cid[0,8]}]\e[0m \e[31mtimeout\e[0m" if ids.size > 1
        next
      end
      p = reply.payload
      next say("top: #{p[:error]}") if p&.dig(:error)
      next unless p

      puts "\e[90m[#{cid[0,8]}]\e[0m" if ids.size > 1
      puts
      puts "  \e[1mUptime:\e[0m #{fmt_uptime(p[:uptime].to_f)}    " \
           "\e[1mLoad:\e[0m #{p[:load_1]} #{p[:load_5]} #{p[:load_15]}    " \
           "\e[1mCPUs:\e[0m #{p[:cpu_count]}"
      puts

      cpu = p[:cpu_percent].to_f
      puts "  \e[1mCPU:\e[0m  #{bar(cpu)}  #{'%5.1f' % cpu}%"

      mt = p[:mem_total].to_f; mu = p[:mem_used].to_f
      mp = mt > 0 ? (mu / mt * 100) : 0
      puts "  \e[1mMem:\e[0m  #{bar(mp)}  #{'%5.1f' % mp}%  (#{fmt_bytes(mu)} / #{fmt_bytes(mt)})"

      st = p[:swap_total].to_f
      if st > 0
        su = p[:swap_used].to_f
        sp = st > 0 ? (su / st * 100) : 0
        puts "  \e[1mSwap:\e[0m #{bar(sp)}  #{'%5.1f' % sp}%  (#{fmt_bytes(su)} / #{fmt_bytes(st)})"
      end

      disks = p[:disks]
      if disks && !disks.empty?
        puts
        puts "  \e[1mDisk:\e[0m"
        disks.each do |d|
          pct = d[:percent].to_f rescue 0
          puts "    %-14s #{bar(pct, 16)}  %5.1f%%  (%s / %s)" % [
            d[:mount].to_s[0,14], pct, fmt_bytes(d[:used].to_i), fmt_bytes(d[:total].to_i)]
        end
      end
      puts
    end
  end

  def cmd_reboot
    ids = target_ids
    names = ids.map { |i| i[0,8] }.join(", ")
    print "  \e[31mReboot #{names}? [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"
    ids.each do |cid|
      reply = request(cid, "sys_reboot", nil, timeout: 5)
      status = reply&.payload&.dig(:status) || "no response"
      say "[#{cid[0,8]}] #{status}"
    end
  end

  def cmd_shutdown
    ids = target_ids
    names = ids.map { |i| i[0,8] }.join(", ")
    print "  \e[31mShutdown #{names}? [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"
    ids.each do |cid|
      reply = request(cid, "sys_shutdown", nil, timeout: 5)
      status = reply&.payload&.dig(:status) || "no response"
      say "[#{cid[0,8]}] #{status}"
    end
  end

  # ── client: network ────────────────────────────────────────────────────

  def cmd_ifconfig
    ids = target_ids
    ids.each do |cid|
      reply = request(cid, "net_ifconfig", nil, timeout: 10)
      unless reply
        puts "\e[90m[#{cid[0,8]}]\e[0m \e[31mtimeout\e[0m" if ids.size > 1
        next
      end
      p = reply.payload
      next say("ifconfig: #{p[:error]}") if p&.dig(:error)

      puts "\e[90m[#{cid[0,8]}]\e[0m" if ids.size > 1
      ifaces = p[:interfaces]
      next unless ifaces

      ifaces.each do |name, info|
        state_color = info[:state].to_s == "up" ? "\e[32m" : "\e[90m"
        puts "  \e[1m#{name}:\e[0m  #{state_color}#{info[:state]}\e[0m  MTU #{info[:mtu]}"

        if info[:mac] && info[:mac].to_s != "00:00:00:00:00:00"
          puts "    MAC:  #{info[:mac]}"
        end
        if info[:ipv4]
          Array(info[:ipv4]).each { |a| puts "    IPv4: #{a}" }
        end
        if info[:ipv6]
          Array(info[:ipv6]).each { |a| puts "    IPv6: #{a}" }
        end

        rx = info[:rx_bytes].to_i rescue 0
        tx = info[:tx_bytes].to_i rescue 0
        rp = info[:rx_packets].to_i rescue 0
        tp = info[:tx_packets].to_i rescue 0
        if rx > 0 || tx > 0
          puts "    RX:   #{fmt_bytes(rx)} (#{rp} pkts)    TX: #{fmt_bytes(tx)} (#{tp} pkts)"
        end
        puts
      end
    end
  end

  def cmd_netstat(rest)
    mode = rest&.strip&.downcase
    mode = "listening" if mode.nil? || mode.empty?

    ids = target_ids
    ids.each do |cid|
      reply = request(cid, "net_netstat", { mode: mode }, timeout: 10)
      unless reply
        puts "\e[90m[#{cid[0,8]}]\e[0m \e[31mtimeout\e[0m" if ids.size > 1
        next
      end
      p = reply.payload
      next say("netstat: #{p[:error]}") if p&.dig(:error)

      puts "\e[90m[#{cid[0,8]}]\e[0m" if ids.size > 1
      sockets = p[:sockets]
      next unless sockets

      fmt = "  %-6s %-28s %-28s %s"
      lines = []
      lines << format(fmt, "PROTO", "LOCAL ADDRESS", "PEER ADDRESS", "PROCESS")
      lines << "  " + "-" * 76
      sockets.each do |s|
        lines << format(fmt,
          s[:proto].to_s,
          s[:local].to_s[0,28],
          s[:peer].to_s[0,28],
          s[:process].to_s)
      end
      paged(lines)
    end
  end

  # ── client: sessions ──────────────────────────────────────────────────

  def cmd_sessions(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when nil, "list"
      if multi_target?
        print_multi(parallel_request("sys_who", nil, timeout: 10)) do |r|
          p = r.payload
          next ["error: #{p[:error]}"] if p&.dig(:error)
          sessions = p&.dig(:sessions)
          next ["(no sessions)"] unless sessions && !sessions.empty?
          lines = [format("%-12s %-10s %-18s %-8s %s", "USER", "TTY", "LOGIN", "IDLE", "PID")]
          sessions.each do |s|
            lines << format("%-12s %-10s %-18s %-8s %s",
              s[:user], s[:tty], "#{s[:date]} #{s[:time]}", s[:idle], s[:pid])
          end
          lines
        end
      else
        reply = request(target_ids.first, "sys_who", nil, timeout: 10)
        return unless reply
        p = reply.payload
        return say("sessions: #{p[:error]}") if p&.dig(:error)
        sessions = p&.dig(:sessions)
        return say("no sessions") unless sessions && !sessions.empty?
        fmt = "  %-12s %-10s %-18s %-8s %s"
        puts format(fmt, "USER", "TTY", "LOGIN", "IDLE", "PID")
        puts "  " + "-" * 56
        sessions.each do |s|
          puts format(fmt, s[:user], s[:tty], "#{s[:date]} #{s[:time]}", s[:idle], s[:pid])
        end
      end

    when "kill"
      tty = args&.strip
      return say("usage: sessions kill <tty>") unless tty && !tty.empty?
      return say("sessions kill requires a single client") if multi_target?

      print "  \e[31mKill all processes on #{tty}? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"

      reply = request(target_ids.first, "session_kill", { tty: tty }, timeout: 10)
      return unless reply
      p = reply.payload
      p&.dig(:error) ? say("kill: #{p[:error]}") : say(p[:status].to_s)

    when "write"
      parts = args&.split(" ", 2)
      return say("usage: sessions write <tty> <message>") unless parts && parts.size == 2
      return say("sessions write requires a single client") if multi_target?
      tty, message = parts
      reply = request(target_ids.first, "session_write", { tty: tty, message: message }, timeout: 10)
      return unless reply
      p = reply.payload
      p&.dig(:error) ? say("write: #{p[:error]}") : say(p[:status].to_s)

    when "listen"
      if args&.strip&.downcase == "stop"
        if @listen_sessions.empty?
          say "no active listen sessions"
        else
          @listen_sessions.each do |listen_id, info|
            send_req(info[:client_id], "session_listen_stop", { listen_id: listen_id })
          end
          say "stopped #{@listen_sessions.size} listen session(s)"
          @listen_sessions.clear
        end
      else
        tty = args&.strip
        return say("usage: sessions listen <tty> | sessions listen stop") unless tty && !tty.empty?
        return say("sessions listen requires a single client") if multi_target?

        req_id = SecureRandom.hex(4)
        queue = @waiter.register(req_id)
        send_req(target_ids.first, "session_listen", { tty: tty }, id: req_id)

        begin
          reply = Timeout.timeout(10) { queue.pop }
          p = reply.payload
          if p&.dig(:error)
            say "listen: #{p[:error]}"
          else
            listen_id = p[:listen_id].to_s
            @listen_sessions[listen_id] = { client_id: target_ids.first, tty: tty }
            say "listening on #{tty} — type 'sessions listen stop' to end"
          end
        rescue Timeout::Error
          say "listen: timeout"
        ensure
          @waiter.unregister(req_id)
        end
      end

    else
      puts <<~TXT
        sessions                       list logged-in users
        sessions kill <tty>            kill all processes on tty
        sessions write <tty> <msg>     write message to user's terminal
        sessions listen <tty>          spy on terminal output (needs root + strace)
        sessions listen stop           stop all listen sessions
      TXT
    end
  end

  # ── pager helper ─────────────────────────────────────────────────────

  def paged(lines)
    if lines.size > 30 && $stdout.tty?
      IO.popen("less -R", "w") do |pager|
        lines.each { |l| pager.puts l }
      end
    else
      lines.each { |l| puts l }
    end
  rescue Errno::EPIPE
    # User quit pager early
  end

  # ── client: interactive shell ──────────────────────────────────────────

  def cmd_shell
    sid = target_ids.first
    return say("client offline") unless sid

    req_id = SecureRandom.hex(4)
    queue = @waiter.register(req_id)
    send_req(sid, "shell_open", nil, id: req_id)

    begin
      reply = Timeout.timeout(10) { queue.pop }
      p = reply.payload
      if p&.dig(:error)
        say "shell: #{p[:error]}"
        return
      end
    rescue Timeout::Error
      say "shell: timeout opening shell"
      return
    ensure
      @waiter.unregister(req_id)
    end

    @shell_active = req_id
    @shell_closed = false
    $current_prompt = ""

    say "shell opened — type '~.' to return to shisa"
    sleep 0.3

    begin
      loop do
        break if @shell_closed
        line = $stdin.gets
        break if line.nil?
        line = line.chomp

        if line == "~."
          break
        end

        send_req(sid, "shell_data", { data: line + "\n" }, id: req_id)

        if line.strip == "exit"
          sleep 0.5
          break
        end
      end
    rescue Interrupt
      send_req(sid, "shell_data", { data: "\x03" }, id: req_id)
      retry
    ensure
      @shell_active = nil
      send_req(sid, "shell_close", nil, id: req_id) rescue nil
      $current_prompt = prompt_string
      say "shell closed"
    end
  end

  # ── client: memfile (in-memory scripts) ────────────────────────────────

  def cmd_memfile(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "create", "edit"
      name = args&.strip
      return say("usage: memfile edit <name>") unless name && !name.empty?

      tmpfile = Tempfile.new(["shisa_memfile_", File.extname(name)])
      begin
        # Download existing content if any
        reply = request(target_ids.first, "memfile_read", { name: name }, timeout: 10)
        if reply && reply.payload && reply.payload[:data]
          content = Base64.decode64(reply.payload[:data].to_s)
          File.binwrite(tmpfile.path, content)
        end

        editor = ENV["EDITOR"] || ENV["VISUAL"] || "nano"
        system(editor, tmpfile.path)

        content = File.binread(tmpfile.path)
        b64 = Base64.strict_encode64(content)
        reply = request(target_ids.first, "memfile_write", { name: name, data: b64 }, timeout: 10)
        if reply && reply.payload
          p = reply.payload
          p[:error] ? say("memfile: #{p[:error]}") : say(p[:status].to_s)
        end
      ensure
        tmpfile.close
        tmpfile.unlink
      end

    when "exec", "run"
      parts = args&.split(" ", 2) || []
      name = parts[0]
      return say("usage: memfile exec <name> [interpreter]") unless name && !name.empty?
      interpreter = parts[1]&.strip
      payload = { name: name }
      payload[:interpreter] = interpreter if interpreter && !interpreter.empty?
      reply = request(target_ids.first, "memfile_exec", payload, timeout: 120)
      return unless reply
      p = reply.payload
      return say("memfile exec: #{p[:error]}") if p&.dig(:error)
      out = p[:stdout]&.to_s
      err = p[:stderr]&.to_s
      puts out if out && !out.empty?
      $stderr.puts "\e[31m#{err}\e[0m" if err && !err.empty?
      code = p[:exit_code]
      say "\e[33m[exit #{code}]\e[0m" if code && code != 0

    when "cat", "show"
      name = args&.strip
      return say("usage: memfile cat <name>") unless name && !name.empty?
      reply = request(target_ids.first, "memfile_read", { name: name }, timeout: 10)
      return unless reply
      p = reply.payload
      return say("memfile: #{p[:error]}") if p&.dig(:error)
      content = Base64.decode64(p[:data].to_s)
      puts content

    when "list", "ls", nil
      reply = request(target_ids.first, "memfile_list", nil, timeout: 10)
      return unless reply
      p = reply.payload
      files = p&.dig(:files)
      return say("no memfiles") unless files && !files.empty?
      files.each do |f|
        puts "  %-24s %s" % [f[:name], fmt_bytes(f[:size].to_i)]
      end

    when "delete", "rm"
      name = args&.strip
      return say("usage: memfile delete <name>") unless name && !name.empty?
      reply = request(target_ids.first, "memfile_delete", { name: name }, timeout: 10)
      return unless reply
      p = reply.payload
      p&.dig(:error) ? say("memfile: #{p[:error]}") : say(p[:status].to_s)

    when "upload", "ul"
      parts = args&.split(" ", 2)
      return say("usage: memfile upload <local-path> <name>") unless parts && parts.size == 2
      local_path, name = parts
      return say("local file not found: #{local_path}") unless File.exist?(local_path)

      content = File.binread(local_path)
      b64 = Base64.strict_encode64(content)
      reply = request(target_ids.first, "memfile_write", { name: name, data: b64 }, timeout: 30)
      if reply && reply.payload
        p = reply.payload
        p[:error] ? say("memfile: #{p[:error]}") : say("uploaded #{fmt_bytes(content.bytesize)} -> memfile '#{name}'")
      end

    else
      puts <<~TXT
        memfile edit <name>            create/edit in local editor, store in memory
        memfile upload <path> <name>   upload local file to client's memory
        memfile exec <name> [interp]   execute (default: bash). Never touches disk.
        memfile cat <name>             view contents
        memfile list                   list all in-memory files
        memfile delete <name>          delete from memory
      TXT
    end
  end

  # ── client: cron ──────────────────────────────────────────────────────

  def cmd_cron(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when nil, "list", "ls"
      user = args&.strip
      payload = user && !user.empty? ? { user: user } : nil

      if multi_target?
        print_multi(parallel_request("cron_list", payload, timeout: 10)) do |r|
          p = r.payload
          next ["error: #{p[:error]}"] if p&.dig(:error)
          entries = p&.dig(:entries)
          next ["(empty)"] unless entries && !entries.empty?
          entries.map.with_index { |e, i| format("%3d  %s", i, e) }
        end
      else
        reply = request(target_ids.first, "cron_list", payload, timeout: 10)
        return unless reply
        p = reply.payload
        return say("cron: #{p[:error]}") if p&.dig(:error)
        entries = p&.dig(:entries)
        return say("crontab is empty") unless entries && !entries.empty?
        lines = entries.map.with_index { |e, i| format("  %3d  %s", i, e) }
        paged(lines)
      end

    when "add"
      entry = args&.strip
      return say("usage: cron add <min> <hr> <dom> <mon> <dow> <command>") unless entry && !entry.empty?

      ids = target_ids
      ids.each do |cid|
        reply = request(cid, "cron_add", { entry: entry }, timeout: 10)
        if reply && reply.payload
          p = reply.payload
          prefix = ids.size > 1 ? "[#{cid[0,8]}] " : ""
          p[:error] ? say("#{prefix}cron add: #{p[:error]}") : say("#{prefix}#{p[:status]}")
        end
      end

    when "remove", "rm", "delete"
      idx = args&.strip&.to_i
      return say("usage: cron remove <index>") unless idx
      return say("cron remove requires a single client") if multi_target?

      reply = request(target_ids.first, "cron_remove", { index: idx }, timeout: 10)
      return unless reply
      p = reply.payload
      p&.dig(:error) ? say("cron remove: #{p[:error]}") : say(p[:status].to_s)

    else
      puts <<~TXT
        cron [list] [user]             list cron entries (with index numbers)
        cron add <entry>               add a cron entry (full cron line)
        cron remove <index>            remove entry by index number
      TXT
    end
  end

  # ── client: journal / syslog ──────────────────────────────────────────

  def cmd_journal(rest)
    opts = {}
    args = rest&.split || []

    i = 0
    while i < args.size
      case args[i]
      when "-u", "--unit"
        opts[:unit] = args[i + 1]; i += 2
      when "-g", "--grep"
        opts[:grep] = args[i + 1]; i += 2
      when "-n", "--lines"
        opts[:lines] = args[i + 1].to_i; i += 2
      when "-p", "--priority"
        opts[:priority] = args[i + 1]; i += 2
      when "--since"
        opts[:since] = args[i + 1]; i += 2
      when "-b", "--boot"
        opts[:boot] = (args[i + 1] =~ /^-/ || i + 1 >= args.size) ? "0" : args[i += 1]
        i += 1
      when "-h", "--help"
        puts <<~TXT
          journal [-u unit] [-g grep] [-n lines] [-p priority] [--since time] [-b boot]

            -u, --unit <name>      filter by systemd unit (e.g., nginx, sshd)
            -g, --grep <pattern>   filter by regex pattern
            -n, --lines <N>        number of lines (default 100)
            -p, --priority <P>     filter by priority (emerg..debug, or 0..7)
            --since <time>         show entries since (e.g., "1 hour ago", "today")
            -b, --boot [N]         show entries from boot N (default: current)
        TXT
        return
      else
        opts[:unit] ||= args[i]
        i += 1
      end
    end

    payload = opts.empty? ? nil : opts

    if multi_target?
      print_multi(parallel_request("journal_query", payload, timeout: 30)) do |r|
        p = r.payload
        next ["error: #{p[:error]}"] if p&.dig(:error)
        lines = p&.dig(:lines)
        next ["(empty)"] unless lines && !lines.empty?
        lines.map(&:to_s)
      end
    else
      reply = request(target_ids.first, "journal_query", payload, timeout: 30)
      return unless reply
      p = reply.payload
      return say("journal: #{p[:error]}") if p&.dig(:error)
      lines = p&.dig(:lines)
      return say("no log entries") unless lines && !lines.empty?
      paged(lines.map(&:to_s))
    end
  end

  # ── client: daemon control (restart / migrate / kill) ────────────────

  def cmd_restart
    ids = target_ids
    names = ids.map { |i| i[0,8] }.join(", ")
    print "  \e[33mRestart daemon on #{names}? [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"

    ids.each do |cid|
      reply = request(cid, "daemon_restart", nil, timeout: 5)
      if reply && reply.payload
        p = reply.payload
        p[:error] ? say("[#{cid[0,8]}] #{p[:error]}") : say("[#{cid[0,8]}] #{p[:status]}")
      else
        say "[#{cid[0,8]}] sent restart (client will reconnect)"
      end
    end
  end

  def cmd_migrate(rest)
    return say("migrate requires a single client") if multi_target?
    path = rest&.strip
    return say("usage: migrate <target-path>  (e.g. /opt/shisa/client)") if path.nil? || path.empty?

    sid = target_ids.first
    return say("client offline") unless sid

    print "  \e[33mMigrate daemon to #{path}? [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"

    # Option: push a new binary via transfer, or just tell client to copy itself
    # For now, client copies its own binary to the new path and re-execs.
    reply = request(sid, "daemon_migrate", { path: path }, timeout: 15)
    if reply && reply.payload
      p = reply.payload
      p[:error] ? say("migrate: #{p[:error]}") : say(p[:status].to_s)
    else
      say "sent migrate (client will reconnect from #{path})"
    end
  end

  def cmd_kill_daemon
    ids = target_ids
    names = ids.map { |i| i[0,8] }.join(", ")
    print "  \e[31mKill daemon on #{names}? This will NOT restart. [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"

    ids.each do |cid|
      reply = request(cid, "daemon_kill", nil, timeout: 5)
      if reply && reply.payload
        say "[#{cid[0,8]}] #{reply.payload[:status]}"
      else
        say "[#{cid[0,8]}] sent kill"
      end
    end
  end

  # ── client: daemonize ───────────────────────────────────────────────

  def cmd_daemonize(rest)
    ids = target_ids
    opts = {}
    args = rest&.split || []
    i = 0
    while i < args.size
      case args[i]
      when "--log", "-l"
        opts[:log] = args[i + 1]; i += 2
      when "--pidfile", "-p"
        opts[:pidfile] = args[i + 1]; i += 2
      else
        i += 1
      end
    end

    names = ids.map { |i| i[0,8] }.join(", ")
    print "  \e[33mDaemonize #{names}? Current process will exit and restart detached. [y/N]\e[0m "
    confirm = $stdin.gets&.chomp
    return unless confirm&.downcase == "y"

    payload = opts.empty? ? nil : opts
    ids.each do |cid|
      reply = request(cid, "daemon_daemonize", payload, timeout: 5)
      if reply && reply.payload
        p = reply.payload
        if p[:error]
          say "[#{cid[0,8]}] #{p[:error]}"
        else
          pid = p[:pid]
          log = p[:log]
          say "[#{cid[0,8]}] daemonized (pid #{pid}, log: #{log})"
        end
      else
        say "[#{cid[0,8]}] sent daemonize (client will reconnect)"
      end
    end
  end

  # ── client: privilege escalation ───────────────────────────────────────

  def cmd_escalate(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    method = sub&.downcase

    unless method && %w[sudo su setuid script].include?(method)
      puts <<~TXT
        \e[1mUsage:\e[0m
          escalate sudo            restart daemon as root via sudo -S
          escalate su              restart daemon as root via su
          escalate setuid          set SUID bit on binary and restart
          escalate script <path>   run custom escalation script on client
      TXT
      return
    end

    sid = target_ids.first
    return unless sid

    payload = { method: method }

    case method
    when "sudo", "su"
      print "  Password: "
      begin
        system("stty -echo") rescue nil
        password = $stdin.gets&.chomp
      ensure
        system("stty echo") rescue nil
        puts
      end
      return say("cancelled") if password.nil? || password.empty?
      payload[:password] = password

    when "setuid"
      print "  \e[33mSet SUID bit and restart? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"

    when "script"
      script_path = args&.strip
      return say("usage: escalate script <path-on-client>") if script_path.nil? || script_path.empty?
      payload[:script] = script_path
    end

    reply = request(sid, "daemon_escalate", payload, timeout: 10)
    if reply && reply.payload
      p = reply.payload
      p[:error] ? say("escalate: #{p[:error]}") : say(p[:status].to_s)
    else
      say "sent escalate (client will reconnect as elevated)"
    end
  end

  # ── client: systemd service management ────────────────────────────────

  def cmd_service(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "list", "ls", nil
      filter = args&.strip
      payload = filter && !filter.empty? ? { filter: filter } : nil

      if multi_target?
        print_multi(parallel_request("svc_list", payload, timeout: 15)) do |r|
          p = r.payload
          next ["error: #{p[:error]}"] if p&.dig(:error)
          svcs = p&.dig(:services)
          next ["(no services)"] unless svcs && !svcs.empty?
          lines = [format("%-28s %-8s %-8s  %s", "SERVICE", "ACTIVE", "SUB", "DESCRIPTION")]
          svcs.each do |s|
            active_color = s[:active].to_s == "active" ? "\e[32m" : "\e[31m"
            lines << format("%-28s #{active_color}%-8s\e[0m %-8s  %s",
              s[:name].to_s[0,28], s[:active], s[:sub], s[:description].to_s[0,40])
          end
          lines
        end
      else
        reply = request(target_ids.first, "svc_list", payload, timeout: 15)
        return unless reply
        p = reply.payload
        return say("service: #{p[:error]}") if p&.dig(:error)
        svcs = p&.dig(:services)
        return say("no services") unless svcs && !svcs.empty?
        fmt = "  %-28s %-8s %-8s  %s"
        lines = []
        lines << format(fmt, "SERVICE", "ACTIVE", "SUB", "DESCRIPTION")
        lines << "  " + "-" * 76
        svcs.each do |s|
          active_color = s[:active].to_s == "active" ? "\e[32m" : "\e[31m"
          lines << format("  %-28s #{active_color}%-8s\e[0m %-8s  %s",
            s[:name].to_s[0,28], s[:active], s[:sub], s[:description].to_s[0,40])
        end
        paged(lines)
      end

    when "status"
      unit = args&.strip
      return say("usage: service status <unit>") unless unit && !unit.empty?
      return say("service status requires a single client") if multi_target?

      reply = request(target_ids.first, "svc_status", { unit: unit }, timeout: 10)
      return unless reply
      p = reply.payload
      return say("service: #{p[:error]}") if p&.dig(:error)
      puts p[:output].to_s

    when "start", "stop", "restart", "reload", "enable", "disable"
      unit = args&.strip
      return say("usage: service #{sub} <unit>") unless unit && !unit.empty?

      if %w[stop disable].include?(sub) || sub == "restart"
        action_label = sub == "restart" ? "Restart" : sub.capitalize
        ids = target_ids
        names = ids.map { |i| i[0,8] }.join(", ")
        print "  \e[33m#{action_label} #{unit} on #{names}? [y/N]\e[0m "
        confirm = $stdin.gets&.chomp
        return unless confirm&.downcase == "y"
      end

      ids = target_ids
      ids.each do |cid|
        reply = request(cid, "svc_action", { action: sub, unit: unit }, timeout: 15)
        prefix = ids.size > 1 ? "[#{cid[0,8]}] " : ""
        if reply && reply.payload
          p = reply.payload
          if p[:error]
            say "#{prefix}#{p[:error]}"
          elsif p[:exit_code].to_i == 0
            say "#{prefix}#{sub} #{unit}: ok"
          else
            out = p[:stderr]&.to_s
            out = p[:stdout].to_s if out.nil? || out.empty?
            say "#{prefix}#{sub} #{unit}: failed (exit #{p[:exit_code]})"
            say "#{prefix}  #{out.strip}" if out && !out.strip.empty?
          end
        else
          say "#{prefix}timeout"
        end
      end

    when "install"
      if args&.strip =~ /\A(-h|--help|\?)\z/
        puts <<~TXT

          \e[1mservice install\e[0m — install shisa-client as a systemd service

          \e[1mOptions:\e[0m
            --name <name>       unit name            (default: shisa)
            --user <user>       run as this user     (default: root)
            --host <host>       server address       (default: 127.0.0.1)
            --port <port>       server port          (default: 8081)
            --workdir <path>    working directory     (default: binary's directory)
            --description <txt> unit description     (default: Shisa Daemon)

          \e[1mExample:\e[0m
            service install --name shisa --user nobody --port 9090

          \e[1mWorkflow:\e[0m
            escalate sudo              # get root privileges
            migrate /usr/local/bin/shisa  # move binary to system path
            service install             # write unit file + daemon-reload
            service enable shisa      # start on boot
            service start shisa       # start now

        TXT
        return
      end

      return say("service install requires a single client") if multi_target?
      sid = target_ids.first
      return say("client offline") unless sid

      payload = {}
      if args
        parts = args.split
        parts.each_with_index do |a, i|
          case a
          when "--name"        then payload[:name] = parts[i + 1] if parts[i + 1]
          when "--user"        then payload[:user] = parts[i + 1] if parts[i + 1]
          when "--host"        then payload[:host] = parts[i + 1] if parts[i + 1]
          when "--port"        then payload[:port] = parts[i + 1] if parts[i + 1]
          when "--workdir"     then payload[:working_dir] = parts[i + 1] if parts[i + 1]
          when "--description" then payload[:description] = parts[i + 1] if parts[i + 1]
          end
        end
      end

      reply = request(sid, "service_install", payload, timeout: 15)
      return unless reply
      p = reply.payload
      if p&.dig(:error)
        say "install: #{p[:error]}"
      else
        say p[:status].to_s
        puts
        puts "  \e[90mUnit file:\e[0m"
        p[:unit].to_s.each_line { |l| puts "    #{l}" }
        puts
        say "next steps:"
        p[:commands]&.each { |c| puts "    #{c}" }
      end

    else
      puts <<~TXT
        service [list] [filter]        list systemd services
        service status <unit>          show detailed unit status
        service start <unit>           start a service
        service stop <unit>            stop a service (confirmation)
        service restart <unit>         restart a service (confirmation)
        service reload <unit>          reload a service
        service enable <unit>          enable on boot
        service disable <unit>         disable on boot (confirmation)
        service install [--name N] [--user U]  install shisa-client as systemd service
      TXT
    end
  end

  # ── client: watch ──────────────────────────────────────────────────────

  def cmd_watch(rest)
    args = rest&.split || []
    return say("usage: watch [-n sec] <command>") if args.empty?

    interval = 2
    cmd = rest
    if args[0] == "-n" && args.size > 2
      interval = [args[1].to_i, 1].max
      cmd = args[2..].join(" ")
    end

    sid = target_ids.first
    return say("client offline") unless sid

    begin
      loop do
        system("clear") || print("\e[2J\e[H")
        label = @target ? @target[0, 12] : "@#{@group}"
        puts "  \e[7m Every #{interval}s: #{cmd} on #{label} \e[0m"
        puts

        reply = request(sid, "exec", { cmd: cmd }, timeout: interval + 10)
        if reply && reply.payload
          p = reply.payload
          out = p[:stdout]&.to_s
          err = p[:stderr]&.to_s
          puts out if out && !out.empty?
          $stderr.puts "\e[31m#{err}\e[0m" if err && !err.empty?
        else
          puts "  \e[31m(timeout)\e[0m"
        end

        sleep interval
      end
    rescue Interrupt
      say "watch stopped"
    end
  end

  # ── client: find ───────────────────────────────────────────────────────

  def cmd_find(rest)
    args_list = rest&.split || []
    payload = {}

    i = 0
    while i < args_list.size
      case args_list[i]
      when "-name"                    then payload[:name] = args_list[i + 1]; i += 2
      when "-type"                    then payload[:type] = args_list[i + 1]; i += 2
      when "-size"                    then payload[:size] = args_list[i + 1]; i += 2
      when "-mtime"                   then payload[:mtime] = args_list[i + 1]; i += 2
      when "-maxdepth", "--depth"     then payload[:maxdepth] = args_list[i + 1].to_i; i += 2
      else
        payload[:path] ||= args_list[i]
        i += 1
      end
    end

    if multi_target?
      print_multi(parallel_request("find_files", payload.empty? ? nil : payload, timeout: 30)) do |r|
        p = r.payload
        next ["error: #{p[:error]}"] if p&.dig(:error)
        files = p&.dig(:files)
        next ["(no results)"] unless files && !files.empty?
        files.map(&:to_s)
      end
    else
      reply = request(target_ids.first, "find_files", payload.empty? ? nil : payload, timeout: 30)
      return unless reply
      p = reply.payload
      return say("find: #{p[:error]}") if p&.dig(:error)
      files = p&.dig(:files)
      return say("no results") unless files && !files.empty?
      paged(files.map { |f| "  #{f}" })
    end
  end

  # ── client: pkg (package management) ──────────────────────────────────

  def cmd_pkg(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "list", "ls", nil
      if multi_target?
        print_multi(parallel_request("pkg_action", { action: "list" }, timeout: 30)) do |r|
          p = r.payload
          next ["error: #{p[:error]}"] if p&.dig(:error)
          out = p[:stdout]&.to_s
          next ["(no output)"] unless out && !out.empty?
          ["[#{p[:manager]}]"] + out.lines.first(20).map(&:chomp)
        end
      else
        reply = request(target_ids.first, "pkg_action", { action: "list" }, timeout: 30)
        return unless reply
        p = reply.payload
        return say("pkg: #{p[:error]}") if p&.dig(:error)
        out = p[:stdout]&.to_s
        return say("no output") unless out && !out.empty?
        say "package manager: #{p[:manager]}"
        paged(out.lines.map(&:chomp))
      end

    when "search"
      package = args&.strip
      return say("usage: pkg search <name>") unless package && !package.empty?
      reply = request(target_ids.first, "pkg_action", { action: "search", package: package }, timeout: 30)
      return unless reply
      p = reply.payload
      return say("pkg: #{p[:error]}") if p&.dig(:error)
      out = p[:stdout]&.to_s
      return say("no results") unless out && !out.empty?
      paged(out.lines.map(&:chomp))

    when "install"
      package = args&.strip
      return say("usage: pkg install <name>") unless package && !package.empty?
      ids = target_ids
      names = ids.map { |i| i[0, 8] }.join(", ")
      print "  \e[33mInstall '#{package}' on #{names}? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"

      ids.each do |cid|
        reply = request(cid, "pkg_action", { action: "install", package: package }, timeout: 120)
        prefix = ids.size > 1 ? "[#{cid[0, 8]}] " : ""
        if reply && reply.payload
          p = reply.payload
          if p[:error]
            say "#{prefix}#{p[:error]}"
          elsif p[:exit_code].to_i == 0
            say "#{prefix}installed #{package}"
          else
            err = p[:stderr]&.to_s&.strip
            say "#{prefix}install failed (exit #{p[:exit_code]})"
            say "#{prefix}  #{err}" if err && !err.empty?
          end
        else
          say "#{prefix}timeout"
        end
      end

    when "remove", "uninstall"
      package = args&.strip
      return say("usage: pkg remove <name>") unless package && !package.empty?
      ids = target_ids
      names = ids.map { |i| i[0, 8] }.join(", ")
      print "  \e[31mRemove '#{package}' from #{names}? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"

      ids.each do |cid|
        reply = request(cid, "pkg_action", { action: "remove", package: package }, timeout: 120)
        prefix = ids.size > 1 ? "[#{cid[0, 8]}] " : ""
        if reply && reply.payload
          p = reply.payload
          if p[:error]
            say "#{prefix}#{p[:error]}"
          elsif p[:exit_code].to_i == 0
            say "#{prefix}removed #{package}"
          else
            err = p[:stderr]&.to_s&.strip
            say "#{prefix}remove failed (exit #{p[:exit_code]})"
            say "#{prefix}  #{err}" if err && !err.empty?
          end
        else
          say "#{prefix}timeout"
        end
      end

    when "update"
      ids = target_ids
      ids.each do |cid|
        reply = request(cid, "pkg_action", { action: "update" }, timeout: 120)
        prefix = ids.size > 1 ? "[#{cid[0, 8]}] " : ""
        if reply && reply.payload
          p = reply.payload
          if p[:error]
            say "#{prefix}#{p[:error]}"
          else
            say "#{prefix}update complete" if p[:exit_code].to_i == 0
          end
        else
          say "#{prefix}timeout"
        end
      end

    when "upgrade"
      ids = target_ids
      names = ids.map { |i| i[0, 8] }.join(", ")
      print "  \e[33mUpgrade all packages on #{names}? [y/N]\e[0m "
      confirm = $stdin.gets&.chomp
      return unless confirm&.downcase == "y"

      ids.each do |cid|
        reply = request(cid, "pkg_action", { action: "upgrade" }, timeout: 300)
        prefix = ids.size > 1 ? "[#{cid[0, 8]}] " : ""
        if reply && reply.payload
          p = reply.payload
          if p[:error]
            say "#{prefix}#{p[:error]}"
          elsif p[:exit_code].to_i == 0
            say "#{prefix}upgrade complete"
          else
            say "#{prefix}upgrade failed (exit #{p[:exit_code]})"
          end
        else
          say "#{prefix}timeout"
        end
      end

    when "info"
      package = args&.strip
      return say("usage: pkg info <name>") unless package && !package.empty?
      reply = request(target_ids.first, "pkg_action", { action: "info", package: package }, timeout: 15)
      return unless reply
      p = reply.payload
      return say("pkg: #{p[:error]}") if p&.dig(:error)
      puts p[:stdout].to_s

    else
      puts <<~TXT
        pkg [list]               list installed packages
        pkg search <name>        search for packages
        pkg install <name>       install a package (confirmation)
        pkg remove <name>        remove a package (confirmation)
        pkg update               update package index
        pkg upgrade              upgrade all packages (confirmation)
        pkg info <name>          show package details
      TXT
    end
  end

  # ── client: route management ──────────────────────────────────────────

  def cmd_route(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]

    case sub&.downcase
    when nil, "show", "list"
      reply = request(target_ids.first, "exec", { cmd: "ip route show" }, timeout: 10)
      return unless reply
      p = reply.payload
      return say("route: #{p[:error]}") if p&.dig(:error)
      puts p[:stdout].to_s

    when "add"
      return say("usage: route add <destination> via <gateway> [dev <iface>]") unless args && !args.empty?

      # Guardrail: warn if touching default route
      if args.include?("default") || args.match?(/\b0\.0\.0\.0\/0\b/)
        puts "  \e[31m[!] WARNING: Modifying the default route may disconnect this client!\e[0m"
        print "  \e[33mProceed? [y/N]\e[0m "
        confirm = $stdin.gets&.chomp
        return unless confirm&.downcase == "y"
      end

      cmd = "ip route add #{args}"
      reply = request(target_ids.first, "exec", { cmd: cmd }, timeout: 10)
      return unless reply
      p = reply.payload
      if p&.dig(:exit_code).to_i == 0
        say "route added"
      else
        say "route add failed: #{(p[:stderr] || p[:stdout]).to_s.strip}"
      end

    when "del", "delete"
      return say("usage: route del <destination> [via <gateway>]") unless args && !args.empty?

      if args.include?("default") || args.match?(/\b0\.0\.0\.0\/0\b/)
        puts "  \e[31m[!] WARNING: Deleting the default route WILL disconnect this client!\e[0m"
        print "  \e[33mAre you sure? [y/N]\e[0m "
        confirm = $stdin.gets&.chomp
        return unless confirm&.downcase == "y"
      end

      # Check if route carries our connection
      client_host = @server.clients[target_ids.first]&.dig(:host, 0)
      if client_host && args.include?(client_host.to_s)
        puts "  \e[31m[!] WARNING: This route appears to carry the client's connection to us (#{client_host})!\e[0m"
        print "  \e[33mThis will likely kill the connection. Proceed? [y/N]\e[0m "
        confirm = $stdin.gets&.chomp
        return unless confirm&.downcase == "y"
      end

      cmd = "ip route del #{args}"
      reply = request(target_ids.first, "exec", { cmd: cmd }, timeout: 10)
      return unless reply
      p = reply.payload
      if p&.dig(:exit_code).to_i == 0
        say "route deleted"
      else
        say "route del failed: #{(p[:stderr] || p[:stdout]).to_s.strip}"
      end

    when "replace"
      return say("usage: route replace <destination> via <gateway> [dev <iface>]") unless args && !args.empty?

      if args.include?("default") || args.match?(/\b0\.0\.0\.0\/0\b/)
        puts "  \e[31m[!] WARNING: Replacing the default route may disconnect this client!\e[0m"
        print "  \e[33mProceed? [y/N]\e[0m "
        confirm = $stdin.gets&.chomp
        return unless confirm&.downcase == "y"
      end

      cmd = "ip route replace #{args}"
      reply = request(target_ids.first, "exec", { cmd: cmd }, timeout: 10)
      return unless reply
      p = reply.payload
      if p&.dig(:exit_code).to_i == 0
        say "route replaced"
      else
        say "route replace failed: #{(p[:stderr] || p[:stdout]).to_s.strip}"
      end

    when "-h", "--help", "?"
      puts <<~TXT

        \e[1mroute\e[0m — manage client routing table (ip route wrapper)

        \e[1mCommands:\e[0m
          route [show]                      display routing table
          route add <dst> via <gw> [dev X]  add a route
          route del <dst> [via <gw>]        delete a route
          route replace <dst> via <gw>      add or replace a route

        \e[1mExamples:\e[0m
          route                                   show all routes
          route add 10.0.0.0/8 via 192.168.1.1    add a static route
          route del 10.0.0.0/8                     remove a route
          route replace default via 192.168.1.1    change default gateway

        \e[1mGuardrails:\e[0m
          - Warns before modifying the default route
          - Warns if a route carries the client's connection to this server
          - All changes require confirmation for dangerous operations

      TXT

    else
      say "unknown route subcommand '#{sub}'. Use: show, add, del, replace, -h"
    end
  end

  # ── script (macro record/replay) ──────────────────────────────────────

  def cmd_script(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "record", "rec"
      name = args&.strip
      return say("usage: script record <name>") unless name && !name.empty?
      @recording = true
      @recording_name = name
      @recording_commands = []
      say "recording script '#{name}' — type commands, then 'script stop' to save"

    when "stop"
      unless @recording
        say "not recording"
        return
      end
      if @recording_commands.empty?
        say "no commands recorded, discarded"
      else
        @storage.set_script(@recording_name, @recording_commands)
        say "saved script '#{@recording_name}' (#{@recording_commands.size} commands)"
      end
      @recording = false
      @recording_name = nil
      @recording_commands = []

    when "run", "play", "exec"
      name = args&.strip
      return say("usage: script run <name>") unless name && !name.empty?
      commands = @storage.get_script(name)
      return say("no script '#{name}'") unless commands && !commands.empty?

      say "running script '#{name}' (#{commands.size} commands)..."
      commands.each_with_index do |line, i|
        say "\e[90m[#{i + 1}/#{commands.size}]\e[0m #{line}"
        begin
          cmd, cmd_rest = line.split(" ", 2)
          case cmd.downcase
          when "use", "u"         then cmd_use(cmd_rest)
          when "back", "deselect" then @target = nil; @group = nil
          else
            if @target || @group
              dispatch_client(cmd, cmd_rest)
            else
              dispatch_global(cmd, cmd_rest)
            end
          end
        rescue => e
          say "\e[31merror at command #{i + 1}: #{e.message}\e[0m"
        end
      end
      say "script '#{name}' complete"

    when "list", "ls", nil
      scripts = @storage.all_scripts
      if scripts.empty?
        say "no scripts"
      else
        scripts.each do |name, commands|
          puts "  \e[1m#{name}\e[0m  (#{commands.size} commands)"
        end
      end

    when "show", "cat"
      name = args&.strip
      return say("usage: script show <name>") unless name && !name.empty?
      commands = @storage.get_script(name)
      return say("no script '#{name}'") unless commands && !commands.empty?
      commands.each_with_index do |c, i|
        puts format("  %3d  %s", i + 1, c)
      end

    when "delete", "rm"
      name = args&.strip
      return say("usage: script delete <name>") unless name && !name.empty?
      return say("no script '#{name}'") unless @storage.get_script(name)
      @storage.delete_script(name)
      say "deleted script '#{name}'"

    else
      puts <<~TXT
        script record <name>     start recording commands as a named macro
        script stop              stop recording and save
        script run <name>        replay a script in current context
        script show <name>       show script contents
        script list              list all scripts
        script delete <name>     delete a script
      TXT
    end
  end

  # ── scp (client-to-client transfer) ───────────────────────────────────

  def cmd_scp(rest)
    parts = rest&.split
    return say("usage: scp <src-id>:<path> <dst-id>:<path>") unless parts && parts.size == 2

    src_spec, dst_spec = parts
    src_parts = src_spec.split(":", 2)
    dst_parts = dst_spec.split(":", 2)

    unless src_parts.size == 2 && dst_parts.size == 2
      return say("format: <id>:<path> <id>:<path>")
    end

    src_id, src_path = src_parts
    dst_id, dst_path = dst_parts

    src_hwid = resolve(src_id)
    return unless src_hwid
    dst_hwid = resolve(dst_id)
    return unless dst_hwid

    src_sid = socket_for_hwid(src_hwid)
    dst_sid = socket_for_hwid(dst_hwid)
    return say("source client offline") unless src_sid
    return say("destination client offline") unless dst_sid

    reply = request(src_sid, "exec", { cmd: "if [ -d #{shell_escape(src_path)} ]; then find #{shell_escape(src_path)} -type f 2>/dev/null; else ls -d #{src_path} 2>/dev/null; fi" }, timeout: 15)
    return say("failed to resolve source path") unless reply
    files = reply.payload[:stdout].to_s.strip.lines.map(&:strip).reject(&:empty?)
    return say("no files matching #{src_path}") if files.empty?

    is_multi = files.size > 1
    if is_multi
      say "transferring #{files.size} file(s): #{src_id}:#{src_path} -> #{dst_id}:#{dst_path}"
      request(dst_sid, "exec", { cmd: "mkdir -p #{shell_escape(dst_path)}" }, timeout: 5)
    end

    ok = 0
    files.each_with_index do |f, i|
      tmpfile = Tempfile.new("shisa_scp_")
      begin
        rel = is_multi ? File.basename(f) : nil
        dest = is_multi ? File.join(dst_path, rel) : dst_path
        label = is_multi ? "[#{i + 1}/#{files.size}] #{File.basename(f)}" : f
        print "\r  #{label}: downloading..."

        result = transfer_download(src_sid, f, tmpfile.path)
        unless result[:success]
          say "\n  #{label}: download failed: #{result[:error]}"
          next
        end

        print "\r  #{label}: uploading...   "
        result = transfer_upload(dst_sid, tmpfile.path, dest)
        if result[:success]
          ok += 1
          print "\r  #{label}: #{fmt_bytes(result[:size])}     \n" if is_multi
        else
          say "\n  #{label}: upload failed: #{result[:error]}"
        end
      ensure
        tmpfile.close
        tmpfile.unlink
      end
    end

    if is_multi
      fail_count = files.size - ok
      say "transferred #{ok}/#{files.size} file(s)#{fail_count > 0 ? " (#{fail_count} failed)" : ""}"
    else
      say "transferred: #{src_spec} -> #{dst_spec}" if ok > 0
    end
  end

  # ── client: tunnels ────────────────────────────────────────────────────

  def cmd_forward(rest)
    return say("usage: forward -L <local_port>:<remote_host>:<remote_port>") unless rest

    args = rest.strip.split(" ", 2)
    flag = args[0]
    spec = args[1]

    case flag
    when "-L"
      return say("usage: forward -L <local_port>:<host>:<port>") unless spec
      parts = spec.split(":")
      return say("format: <local_port>:<remote_host>:<remote_port>") unless parts.size == 3
      local_port  = parts[0].to_i
      remote_host = parts[1]
      remote_port = parts[2].to_i

      begin
        sid = target_ids.first
        return say("client offline") unless sid
        num = @tunnel_mgr.forward_local(sid, local_port, remote_host, remote_port)
        say "tunnel ##{num}: 127.0.0.1:#{local_port} -> #{remote_host}:#{remote_port} via #{@target[0,8]}"
      rescue => e
        say "forward failed: #{e.message}"
      end

    when "-R"
      return say("usage: forward -R <remote_port>:<local_host>:<local_port>") unless spec
      parts = spec.split(":")
      return say("format: <remote_port>:<local_host>:<local_port>") unless parts.size == 3
      remote_port = parts[0].to_i
      local_host  = parts[1]
      local_port  = parts[2].to_i

      begin
        sid = target_ids.first
        return say("client offline") unless sid
        num = @tunnel_mgr.forward_remote(sid, remote_port, local_host, local_port)
        say "tunnel ##{num}: client:#{remote_port} -> #{local_host}:#{local_port} via #{@target[0,8]}"
      rescue => e
        say "forward failed: #{e.message}"
      end

    else
      say "usage: forward -L <local_port>:<host>:<port>  or  forward -R <remote_port>:<host>:<port>"
    end
  end

  def cmd_tunnels
    local_tunnels  = @tunnel_mgr.list
    remote_tunnels = @tunnel_mgr.list_remote
    if local_tunnels.empty? && remote_tunnels.empty?
      say "no active tunnels"
      return
    end
    fmt = "  %3s  %-4s %-24s %-24s %-10s %s"
    puts format(fmt, "#", "TYPE", "LISTEN", "TARGET", "CLIENT", "CONNS")
    puts "  " + "-" * 80
    local_tunnels.each do |t|
      conns = @tunnel_mgr.connection_count(t.num)
      puts format(fmt, t.num, "-L",
        "server:#{t.local_port}",
        "#{t.remote_host}:#{t.remote_port}",
        t.client_id[0,10],
        conns.to_s)
    end
    remote_tunnels.each do |t|
      conns = @tunnel_mgr.connection_count(t.num)
      puts format(fmt, t.num, "-R",
        "client:#{t.remote_port}",
        "#{t.local_host}:#{t.local_port}",
        t.client_id[0,10],
        conns.to_s)
    end
  end

  def cmd_tunnel(rest)
    sub, args = rest&.split(" ", 2) || [nil, nil]
    case sub&.downcase
    when "close", "kill"
      num = args&.strip&.to_i
      return say("usage: tunnel close <#>") unless num && num > 0
      if @tunnel_mgr.close_listener(num)
        say "closed tunnel ##{num}"
      else
        say "tunnel ##{num} not found"
      end
    else
      say "usage: tunnel close <#>"
    end
  end

  # ── transfer implementation ────────────────────────────────────────────

  def transfer_download(client_id, remote_path, local_path)
    req_id = SecureRandom.hex(4)
    queue  = @waiter.register(req_id)
    send_req(client_id, "transfer_request", { path: remote_path }, id: req_id)

    meta = nil
    begin
      Timeout.timeout(15) do
        env = queue.pop
        case env.event
        when "transfer_error"
          return { success: false, error: env.payload&.dig(:error) || "remote error" }
        when "transfer_start"
          meta = env.payload
        else
          return { success: false, error: "unexpected: #{env.event}" }
        end
      end
    rescue Timeout::Error
      return { success: false, error: "timeout waiting for transfer start" }
    end

    total_size   = meta[:total_size].to_i
    expected_sha = meta[:sha256].to_s
    received     = 0
    chunks       = []

    begin
      Timeout.timeout(600) do
        loop do
          env = queue.pop
          case env.event
          when "transfer_chunk"
            data = Base64.decode64(env.payload[:data].to_s)
            chunks << data
            received += data.bytesize
            pct = total_size > 0 ? (received * 100.0 / total_size).round(1) : 100
            print "\r  #{fmt_bytes(received)} / #{fmt_bytes(total_size)} (#{pct}%)"
          when "transfer_done"
            puts
            break
          when "transfer_error"
            puts
            return { success: false, error: env.payload&.dig(:error) || "transfer error" }
          end
        end
      end
    rescue Timeout::Error
      puts
      return { success: false, error: "transfer timed out" }
    ensure
      @waiter.unregister(req_id)
    end

    file_data = chunks.join.b
    sha = Digest::SHA256.hexdigest(file_data)
    if sha != expected_sha
      return { success: false, error: "SHA256 mismatch (expected #{expected_sha[0,8]}…, got #{sha[0,8]}…)" }
    end

    File.binwrite(local_path, file_data)
    { success: true, size: file_data.bytesize }
  end

  def transfer_upload(client_id, local_path, remote_path)
    data       = File.binread(local_path)
    sha        = Digest::SHA256.hexdigest(data)
    total_size = data.bytesize
    req_id     = SecureRandom.hex(4)
    queue      = @waiter.register(req_id)

    send_req(client_id, "transfer_push", {
      path: remote_path, total_size: total_size, chunk_size: CHUNK_SIZE, sha256: sha,
    }, id: req_id)

    offset = 0
    while offset < total_size
      chunk_end = [offset + CHUNK_SIZE, total_size].min
      chunk     = data.byteslice(offset, chunk_end - offset)
      send_req(client_id, "transfer_chunk", { index: offset / CHUNK_SIZE, data: Base64.strict_encode64(chunk) }, id: req_id)
      offset = chunk_end
      pct = total_size > 0 ? (offset * 100.0 / total_size).round(1) : 100
      print "\r  #{fmt_bytes(offset)} / #{fmt_bytes(total_size)} (#{pct}%)"
    end

    send_req(client_id, "transfer_done", nil, id: req_id)
    puts

    begin
      Timeout.timeout(30) do
        env = queue.pop
        if env.event == "transfer_ack"
          p = env.payload
          ok = p && (p[:success] == true || p[:success] == "true")
          ok ? { success: true, size: total_size } : { success: false, error: p&.dig(:error) || "rejected" }
        else
          { success: false, error: "unexpected: #{env.event}" }
        end
      end
    rescue Timeout::Error
      { success: false, error: "timeout waiting for ack" }
    ensure
      @waiter.unregister(req_id)
    end
  end

  # ── reply wiring ───────────────────────────────────────────────────────

  REPLY_EVENTS = %w[
    fs_reply exec_reply sys_reply net_reply session_reply
    memfile_reply cron_reply journal_reply daemon_reply svc_reply shell_ready
    find_reply pkg_reply
    transfer_start transfer_chunk transfer_done transfer_error transfer_ack
  ].freeze

  def register_reply_handlers
    shell = self
    REPLY_EVENTS.each do |evt|
      @server.on(evt) do |_client_id, _srv, env|
        shell.handle_reply(env)
      end
    end

    @server.on("session_data") do |_client_id, _srv, env|
      shell.handle_session_data(env)
    end

    @server.on("shell_output") do |_client_id, _srv, env|
      shell.handle_shell_output(env)
    end

    @server.on("shell_closed") do |_client_id, _srv, env|
      shell.handle_shell_closed(env)
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────

  def request(client_id, event, payload = nil, timeout: 30)
    req_id = SecureRandom.hex(4)
    queue  = @waiter.register(req_id)
    send_req(client_id, event, payload, id: req_id)
    begin
      Timeout.timeout(timeout) { queue.pop }
    rescue Timeout::Error
      say "timed out waiting for #{event} reply"
      nil
    ensure
      @waiter.unregister(req_id)
    end
  end

  def send_req(client_id, event, payload = nil, id: nil)
    @server.send_envelope(
      client_id,
      Protocol::Envelope.new(event: event, id: id, payload: payload)
    )
  end

  # Resolve a user-supplied identifier to a HWID. Checks, in order:
  # alias → HWID exact/prefix → hostname exact/prefix → socket-id fallback.
  def resolve(id)
    # 1. Alias lookup
    if (aliased = @storage.resolve_alias(id))
      if socket_for_hwid(aliased)
        return aliased
      else
        say "alias '#{id}' → #{aliased[0,12]} (offline)"
        return nil
      end
    end

    # Build lookup tables
    hwid_map = {}      # hwid → socket_id
    hostname_map = {}  # hostname → hwid
    @server.clients.each do |sid, c|
      hw = hwid_of(sid)
      next unless hw
      hwid_map[hw] = sid
      hname = c.dig(:sysinfo, :hostname)&.to_s
      hostname_map[hname] = hw if hname && !hname.empty?
    end

    # 2. HWID exact
    return id if hwid_map.key?(id)

    # 3. HWID prefix
    hw_matches = hwid_map.keys.select { |h| h.start_with?(id) }
    return hw_matches.first if hw_matches.size == 1

    # 4. Hostname exact (case-insensitive)
    hostname_map.each do |h, hw|
      return hw if h.downcase == id.downcase
    end

    # 5. Hostname prefix (case-insensitive)
    hn_matches = hostname_map.select { |h, _| h.downcase.start_with?(id.downcase) }
    return hn_matches.values.first if hn_matches.size == 1

    # 6. Socket-ID fallback (convenience for copy-paste from logs)
    @server.clients.each do |sid, _|
      return hwid_of(sid) if sid == id || sid.start_with?(id)
    end

    # Ambiguity reporting
    if hw_matches.size > 1
      say "ambiguous HWID: #{hw_matches.map { |h| h[0,12] }.join(', ')}"
    elsif hn_matches.size > 1
      say "ambiguous hostname: #{hn_matches.keys.join(', ')}"
    else
      say "no client matching '#{id}'"
    end
    nil
  end

  def bar(percent, width = 20)
    pct = [[percent, 0].max, 100].min
    filled = (pct / 100.0 * width).round.to_i
    color = pct > 90 ? "\e[31m" : (pct > 70 ? "\e[33m" : "\e[32m")
    "#{color}#{"█" * filled}\e[90m#{"░" * (width - filled)}\e[0m"
  end

  def fmt_bytes(n)
    n = n.to_i
    return "#{n} B"                       if n < 1024
    return "#{'%.1f' % (n / 1024.0)} KB"  if n < 1024**2
    return "#{'%.1f' % (n / 1024.0**2)} MB" if n < 1024**3
    "#{'%.1f' % (n / 1024.0**3)} GB"
  end

  def fmt_uptime(seconds)
    d = (seconds / 86400).to_i
    h = ((seconds % 86400) / 3600).to_i
    m = ((seconds % 3600) / 60).to_i
    parts = []
    parts << "#{d}d" if d > 0
    parts << "#{h}h" if h > 0
    parts << "#{m}m"
    parts.join(" ")
  end

  def shell_escape(s)
    "'" + s.gsub("'", "'\\''") + "'"
  end

  def download_directory(sid, remote_path, local_path)
    say "listing remote directory #{remote_path}..."
    reply = request(sid, "exec", { cmd: "find #{shell_escape(remote_path)} -type f 2>/dev/null" }, timeout: 30)
    return say("failed to list directory") unless reply
    files = reply.payload[:stdout].to_s.strip.lines.map(&:strip).reject(&:empty?)
    return say("no files found in #{remote_path}") if files.empty?

    say "downloading #{files.size} file(s)..."
    FileUtils.mkdir_p(local_path)
    ok = 0
    files.each_with_index do |f, i|
      rel = f.sub(%r{^#{Regexp.escape(remote_path)}/?}, "")
      dest = File.join(local_path, rel)
      FileUtils.mkdir_p(File.dirname(dest))
      print "\r  [#{i + 1}/#{files.size}] #{rel}"
      result = transfer_download(sid, f, dest)
      ok += 1 if result[:success]
    end
    puts
    fail_count = files.size - ok
    say "downloaded #{ok}/#{files.size} file(s) -> #{local_path}#{fail_count > 0 ? " (#{fail_count} failed)" : ""}"
  end

  def download_glob(sid, pattern, local_path)
    say "resolving #{pattern}..."
    reply = request(sid, "exec", { cmd: "ls -d #{pattern} 2>/dev/null" }, timeout: 10)
    return say("no matches for #{pattern}") unless reply
    files = reply.payload[:stdout].to_s.strip.lines.map(&:strip).reject(&:empty?)
    return say("no matches for #{pattern}") if files.empty?

    say "downloading #{files.size} file(s)..."
    FileUtils.mkdir_p(local_path)
    ok = 0
    files.each_with_index do |f, i|
      dest = File.join(local_path, File.basename(f))
      print "\r  [#{i + 1}/#{files.size}] #{File.basename(f)}"
      result = transfer_download(sid, f, dest)
      ok += 1 if result[:success]
    end
    puts
    fail_count = files.size - ok
    say "downloaded #{ok}/#{files.size} file(s) -> #{local_path}#{fail_count > 0 ? " (#{fail_count} failed)" : ""}"
  end

  def say(line)
    print("\r\e[K#{line}\n")
  end

  def cleanup
    @tunnel_mgr.list.each { |t| @tunnel_mgr.close_listener(t.num) }
    @server.clients.keys.each { |id| @server.disconnect(id) }
    puts "bye"
  end

  # ── help ───────────────────────────────────────────────────────────────

  def help_text
    <<~TXT

      \e[1mShisa Control Shell\e[0m

        use <id|alias|hostname|@group>   select a client or group
        who / list             show connected clients
        broadcast <message>    send a message to all clients
        kick <id>              disconnect a client
        group <sub> [args]     manage client groups
        alias <sub> [args]     manage client aliases
        note <sub> [args]      per-client notes (by HWID)
        script <sub> [args]     record/replay command macros
        scp <s>:<path> <d>:<path>  copy file between two clients
        history [n]            show command history
        refresh                reload authorized client keys
        help                   show this help
        quit                   exit

      Clients are identified by \e[1mHWID\e[0m (stable across reconnects).
      You can also \e[1muse\e[0m a hostname, alias, or \e[1m@group\e[0m.
    TXT
  end

  def client_help_text
    target_label = if @group
      "@#{@group}"
    else
      sid = socket_for_hwid(@target)
      hostname = sid && @server.clients.dig(sid, :sysinfo, :hostname)&.to_s
      hostname && !hostname.empty? ? hostname : @target[0, 12]
    end
    <<~TXT

      \e[1mClient commands\e[0m (target: #{target_label})

      \e[1mFilesystem:\e[0m
        cd <path>              change remote directory
        pwd                    show remote working directory
        ls [path]              list files (with sizes/perms)
        cat <path>             view remote file
        edit <path>            edit remote file in local editor
        mkdir <path>           create directory (recursive)
        rm <path> [-r] [-f]    remove file/directory
        mv <src> <dst>         move/rename
        cp [-r] <src> <dst>    copy file/directory
        chmod <mode> <path>    change permissions
        exec <cmd>             run a shell command
        download <src> <dst>   download (supports glob/dir)
        upload <src> <dst>     upload (supports glob/dir)
        update <local-file>    push file to client's install path

      \e[1mSystem:\e[0m
        ps [filter]            list processes
        top                    CPU / memory / disk snapshot
        df                     disk space usage
        free                   memory usage
        du [path]              directory/file size
        reboot                 reboot the client (confirmation required)
        shutdown               shutdown the client (confirmation required)

      \e[1mNetwork:\e[0m
        ifconfig               show interfaces, addresses, traffic
        netstat [mode]          listening | established | all | udp

      \e[1mSessions:\e[0m
        sessions               list logged-in OS users
        sessions kill <tty>    kill all processes on a tty
        sessions write <tty> <msg>   write to user's terminal
        sessions listen <tty>  spy on terminal (needs root + strace)
        sessions listen stop   stop all listen sessions

      \e[1mShell:\e[0m
        shell                  drop into interactive bash on client
                               type '~.' to return, 'exit' to close

      \e[1mMemfile:\e[0m
        memfile edit <name>    create/edit script in local editor (stored in RAM)
        memfile upload <path> <name>  upload local file to client's memory
        memfile exec <name> [interp]  run script (never touches disk)
        memfile cat <name>     view contents
        memfile list           list in-memory files
        memfile delete <name>  delete from memory

      \e[1mCron:\e[0m
        cron [list] [user]     list cron entries
        cron add <entry>       add a cron entry (full cron line)
        cron remove <index>    remove entry by index

      \e[1mJournal:\e[0m
        journal [-u unit] [-g pattern] [-n lines] [-p priority]
        journal [--since time] [-b boot]
        journal -h             show all journal options

      \e[1mDaemon:\e[0m
        restart                re-exec the client daemon (reconnects)
        daemonize [opts]       detach to background (setsid), writes PID file
                               --log <path>  --pidfile <path>
        migrate <path>         copy daemon to new path and re-exec from there
        kill-daemon            kill the daemon process (no restart)
        escalate sudo          restart as root via sudo (prompts for password)
        escalate su            restart as root via su (prompts for password)
        escalate setuid        set SUID bit on binary and restart
        escalate script <path> run custom escalation script

      \e[1mServices:\e[0m
        service [list] [filter]        list systemd services
        service status <unit>          show unit status
        service start|stop|restart <u> manage a service
        service enable|disable <unit>  boot persistence
        service install [opts]         install shisa-client as systemd service

      \e[1mWatch / Find:\e[0m
        watch [-n sec] <cmd>   periodically run command (Ctrl+C to stop)
        find [path] [options]  search files (-name, -type, -size, -mtime, -maxdepth)

      \e[1mPackages:\e[0m
        pkg [list]             list installed packages
        pkg search <name>      search for packages
        pkg install <name>     install a package (confirmation)
        pkg remove <name>      remove a package (confirmation)
        pkg update / upgrade   update index / upgrade all packages
        pkg info <name>        show package details

      \e[1mScript:\e[0m
        script record <name>   record commands as macro
        script stop            stop recording
        script run <name>      replay a script
        script show <name>     show script contents
        script list            list all scripts
        script delete <name>   delete a script

      \e[1mTransfer:\e[0m
        scp <src>:<path> <dst>:<path>  copy between clients (glob/dir)

      \e[1mTunnels:\e[0m
        forward -L <lport>:<host>:<rport>   local forward (server listens)
        forward -R <rport>:<host>:<lport>   remote forward (client listens)
        tunnels                             list active tunnels
        tunnel close <#>                    close a tunnel

      \e[1mRoute:\e[0m
        route [show]                        display routing table
        route add <dst> via <gw>            add a route (guardrails)
        route del <dst>                     delete a route (guardrails)
        route replace <dst> via <gw>        add or replace a route
        route -h                            show full route help

      \e[1mMeta:\e[0m
        info                   show client system info
        who                    show all clients
        back                   deselect client
        help                   show this help
        quit                   exit
    TXT
  end
end
