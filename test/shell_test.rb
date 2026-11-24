# frozen_string_literal: true

require_relative "test_helper"
require_relative "../src/storage"
require_relative "../src/tunnel_server"
require_relative "../src/shell"

class ReplyWaiterTest < Minitest::Test
  def setup
    @waiter = ReplyWaiter.new
  end

  def test_register_and_resolve
    queue = @waiter.register("req-1")
    Thread.new { @waiter.resolve("req-1", :ok) }
    assert_equal :ok, queue.pop
  end

  def test_unregister_removes_pending
    @waiter.register("req-1")
    @waiter.unregister("req-1")
    @waiter.resolve("req-1", :late)
    # No error — resolve on missing key is a no-op
  end

  def test_multiple_requests_independent
    q1 = @waiter.register("a")
    q2 = @waiter.register("b")
    @waiter.resolve("b", :second)
    @waiter.resolve("a", :first)
    assert_equal :first, q1.pop
    assert_equal :second, q2.pop
  end
end

class ShellHelpersTest < Minitest::Test
  def setup
    @server = MockServer.new
    @shell = Shell.new(@server)
  end

  # ── fmt_bytes ─────────────────────────────────────────────────────────

  def test_fmt_bytes_bytes
    assert_equal "0 B", @shell.send(:fmt_bytes, 0)
    assert_equal "512 B", @shell.send(:fmt_bytes, 512)
    assert_equal "1023 B", @shell.send(:fmt_bytes, 1023)
  end

  def test_fmt_bytes_kb
    assert_equal "1.0 KB", @shell.send(:fmt_bytes, 1024)
    assert_equal "1.5 KB", @shell.send(:fmt_bytes, 1536)
  end

  def test_fmt_bytes_mb
    assert_equal "1.0 MB", @shell.send(:fmt_bytes, 1024 * 1024)
    assert_equal "2.5 MB", @shell.send(:fmt_bytes, (2.5 * 1024 * 1024).to_i)
  end

  def test_fmt_bytes_gb
    assert_equal "1.0 GB", @shell.send(:fmt_bytes, 1024 ** 3)
    assert_equal "4.0 GB", @shell.send(:fmt_bytes, 4 * 1024 ** 3)
  end

  # ── fmt_uptime ────────────────────────────────────────────────────────

  def test_fmt_uptime_minutes_only
    assert_equal "5m", @shell.send(:fmt_uptime, 300)
  end

  def test_fmt_uptime_hours_and_minutes
    assert_equal "2h 30m", @shell.send(:fmt_uptime, 9000)
  end

  def test_fmt_uptime_days
    assert_equal "3d 5h 10m", @shell.send(:fmt_uptime, 3 * 86400 + 5 * 3600 + 600)
  end

  def test_fmt_uptime_zero
    assert_equal "0m", @shell.send(:fmt_uptime, 0)
  end

  # ── bar ─────────────────────────────────────────────────────────────────

  def test_bar_zero
    b = @shell.send(:bar, 0)
    # All empty blocks, green color
    assert_includes b, "\e[32m"
    assert_includes b, "░"
  end

  def test_bar_fifty
    b = @shell.send(:bar, 50, 20)
    assert_includes b, "█"
    assert_includes b, "░"
  end

  def test_bar_hundred
    b = @shell.send(:bar, 100, 20)
    # Full blocks, red color
    assert_includes b, "\e[31m"
    assert_includes b, "█" * 20
  end

  def test_bar_clamps_above_100
    b = @shell.send(:bar, 150, 10)
    assert_includes b, "█" * 10
  end

  def test_bar_clamps_below_0
    b = @shell.send(:bar, -10, 10)
    assert_includes b, "░" * 10
  end

  # ── paged ──────────────────────────────────────────────────────────────

  def test_paged_short_output_prints_directly
    lines = (1..5).map { |i| "line #{i}" }
    output = capture_io { @shell.send(:paged, lines) }.first
    assert_equal lines.join("\n") + "\n", output
  end

  # ── resolve ─────────────────────────────────────────────────────────────

  def test_resolve_by_alias
    # Set up a client with HWID
    @server.clients["sock-1"] = {
      alive: true,
      host: ["127.0.0.1", 9999],
      sysinfo: { hwid: "deadbeef1234", hostname: "server-1" },
    }

    storage = @shell.instance_variable_get(:@storage)
    storage.set_alias("web", "deadbeef1234")

    hwid = @shell.send(:resolve, "web")
    assert_equal "deadbeef1234", hwid
  end

  def test_resolve_by_hostname
    @server.clients["sock-1"] = {
      alive: true,
      host: ["127.0.0.1", 9999],
      sysinfo: { hwid: "aabbccdd", hostname: "lab-pc-42" },
    }

    hwid = @shell.send(:resolve, "lab-pc-42")
    assert_equal "aabbccdd", hwid
  end

  def test_resolve_by_hostname_case_insensitive
    @server.clients["sock-1"] = {
      alive: true,
      host: ["127.0.0.1", 9999],
      sysinfo: { hwid: "aabbccdd", hostname: "Lab-PC-42" },
    }

    hwid = @shell.send(:resolve, "lab-pc-42")
    assert_equal "aabbccdd", hwid
  end

  def test_resolve_by_hwid_prefix
    @server.clients["sock-1"] = {
      alive: true,
      host: ["127.0.0.1", 9999],
      sysinfo: { hwid: "deadbeef12345678", hostname: "host-1" },
    }

    hwid = @shell.send(:resolve, "deadbeef")
    assert_equal "deadbeef12345678", hwid
  end

  def test_resolve_returns_nil_for_unknown
    hwid = @shell.send(:resolve, "nonexistent")
    assert_nil hwid
  end

  def test_resolve_by_hostname_prefix
    @server.clients["sock-1"] = {
      alive: true,
      host: ["127.0.0.1", 9999],
      sysinfo: { hwid: "aabbccdd", hostname: "lab-pc-42" },
    }

    hwid = @shell.send(:resolve, "lab-pc")
    assert_equal "aabbccdd", hwid
  end
end

class ShellTargetResolutionTest < Minitest::Test
  def setup
    @server = MockServer.new
    @shell = Shell.new(@server)

    # Simulate a connected client with HWID
    @server.clients["sock-abc-123"] = {
      alive: true,
      host: ["10.0.0.5", 9999],
      sysinfo: { hwid: "deadbeef12345678", hostname: "lab-pc-1" },
    }
  end

  def test_target_ids_resolves_hwid_to_socket
    @shell.instance_variable_set(:@target, "deadbeef12345678")
    ids = @shell.send(:target_ids)
    assert_equal ["sock-abc-123"], ids
  end

  def test_target_ids_returns_empty_for_offline_hwid
    @shell.instance_variable_set(:@target, "nonexistent_hwid")
    ids = @shell.send(:target_ids)
    assert_equal [], ids
  end

  def test_target_ids_resolves_group_hwids
    storage = @shell.instance_variable_get(:@storage)
    storage.create_group("test-grp")
    storage.add_to_group("test-grp", "deadbeef12345678")
    storage.add_to_group("test-grp", "offline_hwid")

    @shell.instance_variable_set(:@group, "test-grp")
    @shell.instance_variable_set(:@target, nil)
    ids = @shell.send(:target_ids)
    assert_equal ["sock-abc-123"], ids
  end

  def test_hwid_of_returns_hwid
    hwid = @shell.send(:hwid_of, "sock-abc-123")
    assert_equal "deadbeef12345678", hwid
  end

  def test_socket_for_hwid_finds_socket
    sid = @shell.send(:socket_for_hwid, "deadbeef12345678")
    assert_equal "sock-abc-123", sid
  end

  def test_socket_for_hwid_returns_nil_for_unknown
    sid = @shell.send(:socket_for_hwid, "nonexistent")
    assert_nil sid
  end
end

class ShellReplyHandlersTest < Minitest::Test
  def setup
    @server = MockServer.new
    @shell = Shell.new(@server)
  end

  def test_handle_reply_resolves_waiter
    waiter = @shell.instance_variable_get(:@waiter)
    queue = waiter.register("test-id")

    env = OpenStruct.new(event: "fs_reply", id: "test-id", payload: { cwd: "/tmp" })
    @shell.handle_reply(env)

    result = queue.pop
    assert_equal "/tmp", result.payload[:cwd]
  end

  def test_handle_session_data_with_active_session
    @shell.instance_variable_set(:@listen_sessions, { "listen-1" => { client_id: "c1", tty: "pts/0" } })

    env = OpenStruct.new(
      event: "session_data",
      id: "listen-1",
      payload: { data: Base64.strict_encode64("hello") },
    )

    output = capture_io { @shell.handle_session_data(env) }.first
    assert_equal "hello", output
  end

  def test_handle_session_data_ignores_unknown_session
    env = OpenStruct.new(
      event: "session_data",
      id: "unknown",
      payload: { data: Base64.strict_encode64("nope") },
    )

    output = capture_io { @shell.handle_session_data(env) }.first
    assert_empty output
  end

  def test_handle_shell_output_when_active
    @shell.instance_variable_set(:@shell_active, "shell-1")

    env = OpenStruct.new(
      event: "shell_output",
      id: "shell-1",
      payload: { data: Base64.strict_encode64("output text") },
    )

    output = capture_io { @shell.handle_shell_output(env) }.first
    assert_equal "output text", output
  end

  def test_handle_shell_output_ignores_inactive
    @shell.instance_variable_set(:@shell_active, nil)

    env = OpenStruct.new(
      event: "shell_output",
      id: "shell-1",
      payload: { data: Base64.strict_encode64("ignored") },
    )

    output = capture_io { @shell.handle_shell_output(env) }.first
    assert_empty output
  end

  def test_handle_shell_closed_sets_flag
    @shell.instance_variable_set(:@shell_active, "shell-1")
    @shell.instance_variable_set(:@shell_closed, false)

    env = OpenStruct.new(event: "shell_closed", id: "shell-1")
    @shell.handle_shell_closed(env)

    assert @shell.instance_variable_get(:@shell_closed)
  end

  def test_handle_shell_closed_ignores_mismatch
    @shell.instance_variable_set(:@shell_active, "shell-1")
    @shell.instance_variable_set(:@shell_closed, false)

    env = OpenStruct.new(event: "shell_closed", id: "other")
    @shell.handle_shell_closed(env)

    refute @shell.instance_variable_get(:@shell_closed)
  end

  def test_on_client_disconnect_cleans_listen_sessions
    @shell.instance_variable_set(:@listen_sessions, {
      "l1" => { client_id: "c1", tty: "pts/0" },
      "l2" => { client_id: "c2", tty: "pts/1" },
      "l3" => { client_id: "c1", tty: "pts/2" },
    })

    @shell.on_client_disconnect("c1")

    sessions = @shell.instance_variable_get(:@listen_sessions)
    assert_equal 1, sessions.size
    assert sessions.key?("l2")
  end
end
