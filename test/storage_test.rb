# frozen_string_literal: true

require_relative "test_helper"
require_relative "../src/storage"

class StorageTest < Minitest::Test
  def setup
    @tmpfile = Tempfile.new(["glob_test", ".json"])
    @storage = ServerStorage.new(@tmpfile.path)
  end

  def teardown
    @tmpfile.close
    @tmpfile.unlink
  end

  # ── groups ──────────────────────────────────────────────────────────────

  def test_create_group
    @storage.create_group("lab-a")
    assert_includes @storage.group_names, "lab-a"
  end

  def test_delete_group
    @storage.create_group("lab-a")
    @storage.delete_group("lab-a")
    refute_includes @storage.group_names, "lab-a"
  end

  def test_add_to_group
    @storage.create_group("lab-a")
    @storage.add_to_group("lab-a", "hwid-1")
    @storage.add_to_group("lab-a", "hwid-2")
    assert_equal %w[hwid-1 hwid-2], @storage.group_members("lab-a")
  end

  def test_add_to_group_no_duplicates
    @storage.create_group("lab-a")
    @storage.add_to_group("lab-a", "hwid-1")
    @storage.add_to_group("lab-a", "hwid-1")
    assert_equal %w[hwid-1], @storage.group_members("lab-a")
  end

  def test_remove_from_group
    @storage.create_group("lab-a")
    @storage.add_to_group("lab-a", "hwid-1")
    @storage.add_to_group("lab-a", "hwid-2")
    @storage.remove_from_group("lab-a", "hwid-1")
    assert_equal %w[hwid-2], @storage.group_members("lab-a")
  end

  def test_group_members_returns_empty_for_unknown
    assert_equal [], @storage.group_members("nonexistent")
  end

  # ── aliases ─────────────────────────────────────────────────────────────

  def test_set_and_resolve_alias
    @storage.set_alias("web", "hwid-abc")
    assert_equal "hwid-abc", @storage.resolve_alias("web")
  end

  def test_remove_alias
    @storage.set_alias("web", "hwid-abc")
    @storage.remove_alias("web")
    assert_nil @storage.resolve_alias("web")
  end

  def test_all_aliases
    @storage.set_alias("web", "hwid-1")
    @storage.set_alias("db", "hwid-2")
    aliases = @storage.all_aliases
    assert_equal "hwid-1", aliases["web"]
    assert_equal "hwid-2", aliases["db"]
  end

  # ── notes ───────────────────────────────────────────────────────────────

  def test_set_and_get_note
    @storage.set_note("hwid-1", "runs NGINX")
    assert_equal "runs NGINX", @storage.get_note("hwid-1")
  end

  def test_remove_note
    @storage.set_note("hwid-1", "runs NGINX")
    @storage.remove_note("hwid-1")
    assert_nil @storage.get_note("hwid-1")
  end

  def test_all_notes
    @storage.set_note("hwid-1", "web server")
    @storage.set_note("hwid-2", "database")
    notes = @storage.all_notes
    assert_equal 2, notes.size
    assert_equal "web server", notes["hwid-1"]
  end

  def test_get_note_returns_nil_for_unknown
    assert_nil @storage.get_note("nonexistent")
  end

  # ── history ─────────────────────────────────────────────────────────────

  def test_add_and_retrieve_history
    @storage.add_history("ps", target: "hwid-1")
    @storage.add_history("top", target: "hwid-1")
    entries = @storage.recent_history(10)
    assert_equal 2, entries.size
    assert_equal "ps", entries[0]["command"]
    assert_equal "top", entries[1]["command"]
  end

  def test_history_stores_timestamp
    @storage.add_history("ps")
    entry = @storage.recent_history(1).first
    assert_match(/\d{4}-\d{2}-\d{2}/, entry["time"])
  end

  def test_history_truncates_at_1000
    1005.times { |i| @storage.add_history("cmd-#{i}") }
    assert_equal 1000, @storage.recent_history(2000).size
  end

  def test_recent_history_limits_results
    5.times { |i| @storage.add_history("cmd-#{i}") }
    assert_equal 3, @storage.recent_history(3).size
  end

  # ── scripts (macros) ────────────────────────────────────────────────────

  def test_set_and_get_script
    @storage.set_script("deploy", %w[exec stop upload start])
    assert_equal %w[exec stop upload start], @storage.get_script("deploy")
  end

  def test_delete_script
    @storage.set_script("deploy", %w[exec stop])
    @storage.delete_script("deploy")
    assert_nil @storage.get_script("deploy")
  end

  def test_all_scripts
    @storage.set_script("deploy", %w[stop start])
    @storage.set_script("check", %w[ps top])
    scripts = @storage.all_scripts
    assert_equal 2, scripts.size
    assert_equal %w[stop start], scripts["deploy"]
  end

  def test_get_script_returns_nil_for_unknown
    assert_nil @storage.get_script("nonexistent")
  end

  def test_scripts_persist
    @storage.set_script("deploy", %w[stop start])
    reloaded = ServerStorage.new(@tmpfile.path)
    assert_equal %w[stop start], reloaded.get_script("deploy")
  end

  # ── persistence ─────────────────────────────────────────────────────────

  def test_data_persists_across_instances
    @storage.create_group("persist-test")
    @storage.add_to_group("persist-test", "hwid-x")
    @storage.set_alias("px", "hwid-x")
    @storage.set_note("hwid-x", "persistence check")

    reloaded = ServerStorage.new(@tmpfile.path)
    assert_equal %w[hwid-x], reloaded.group_members("persist-test")
    assert_equal "hwid-x", reloaded.resolve_alias("px")
    assert_equal "persistence check", reloaded.get_note("hwid-x")
  end
end
