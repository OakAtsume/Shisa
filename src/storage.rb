# frozen_string_literal: true

require "json"
require "date"
require "fileutils"

class ServerStorage
  def initialize(base_dir = nil)
    @base_dir = base_dir || File.join(File.dirname(__FILE__), "..")
    @db_dir   = File.join(@base_dir, "db")
    @log_dir  = File.join(@base_dir, "logs")
    @mutex    = Mutex.new

    FileUtils.mkdir_p(@db_dir)
    FileUtils.mkdir_p(@log_dir)

    migrate_legacy
  end

  # ── groups ──────────────────────────────────────────────────────────────

  def groups
    load_json("groups") || {}
  end

  def all_groups
    groups
  end

  def create_group(name)
    @mutex.synchronize do
      g = load_json("groups") || {}
      g[name] ||= []
      save_json("groups", g)
    end
  end

  def delete_group(name)
    @mutex.synchronize do
      g = load_json("groups") || {}
      g.delete(name)
      save_json("groups", g)
    end
  end

  def add_to_group(name, client_id)
    @mutex.synchronize do
      g = load_json("groups") || {}
      g[name] ||= []
      g[name] << client_id unless g[name].include?(client_id)
      save_json("groups", g)
    end
  end

  def remove_from_group(name, client_id)
    @mutex.synchronize do
      g = load_json("groups") || {}
      return unless g[name]
      g[name].delete(client_id)
      save_json("groups", g)
    end
  end

  def group_members(name)
    (groups[name] || []).dup
  end

  def group_names
    groups.keys
  end

  # ── aliases ─────────────────────────────────────────────────────────────

  def aliases
    load_json("aliases") || {}
  end

  def all_aliases
    aliases
  end

  def set_alias(name, client_id)
    @mutex.synchronize do
      a = load_json("aliases") || {}
      a[name] = client_id
      save_json("aliases", a)
    end
  end

  def remove_alias(name)
    @mutex.synchronize do
      a = load_json("aliases") || {}
      a.delete(name)
      save_json("aliases", a)
    end
  end

  def resolve_alias(name)
    aliases[name]
  end

  def alias_for(hwid)
    aliases.each { |name, id| return name if id == hwid }
    nil
  end

  # ── notes (keyed by HWID) ────────────────────────────────────────────────

  def notes
    load_json("notes") || {}
  end

  def all_notes
    notes
  end

  def set_note(hwid, text)
    @mutex.synchronize do
      n = load_json("notes") || {}
      n[hwid] = text
      save_json("notes", n)
    end
  end

  def remove_note(hwid)
    @mutex.synchronize do
      n = load_json("notes") || {}
      n.delete(hwid)
      save_json("notes", n)
    end
  end

  def get_note(hwid)
    notes[hwid]
  end

  # ── scripts (command macros) ───────────────────────────────────────────

  def scripts
    load_json("scripts") || {}
  end

  def all_scripts
    scripts
  end

  def set_script(name, commands)
    @mutex.synchronize do
      s = load_json("scripts") || {}
      s[name] = commands
      save_json("scripts", s)
    end
  end

  def get_script(name)
    scripts[name]
  end

  def delete_script(name)
    @mutex.synchronize do
      s = load_json("scripts") || {}
      s.delete(name)
      save_json("scripts", s)
    end
  end

  # ── history (daily log files) ──────────────────────────────────────────

  def add_history(line, target: nil)
    @mutex.synchronize do
      entry = {
        "time"    => Time.now.strftime("%Y-%m-%d %H:%M:%S"),
        "target"  => target,
        "command" => line,
      }
      today = Time.now.strftime("%d-%m-%Y")
      path = File.join(@log_dir, "#{today}.json")
      entries = File.exist?(path) ? (JSON.parse(File.read(path)) rescue []) : []
      entries << entry
      File.write(path, JSON.pretty_generate(entries))
    end
  end

  def recent_history(n = 20)
    logs = Dir.glob(File.join(@log_dir, "*.json")).sort_by { |f|
      d, m, y = File.basename(f, ".json").split("-").map(&:to_i)
      [y || 0, m || 0, d || 0]
    }
    entries = []
    logs.reverse_each do |path|
      begin
        day_entries = JSON.parse(File.read(path))
        entries = day_entries + entries
        break if entries.size >= n
      rescue
        next
      end
    end
    entries.last(n)
  end

  def history
    recent_history(1000)
  end

  # ── event logging ──────────────────────────────────────────────────────

  def log_event(event, data = {})
    @mutex.synchronize do
      entry = {
        "time"  => Time.now.strftime("%Y-%m-%d %H:%M:%S"),
        "event" => event,
      }.merge(data)
      today = Time.now.strftime("%d-%m-%Y")
      path = File.join(@log_dir, "#{today}.json")
      entries = File.exist?(path) ? (JSON.parse(File.read(path)) rescue []) : []
      entries << entry
      File.write(path, JSON.pretty_generate(entries))
    end
  end

  private

  def db_path(name)
    File.join(@db_dir, "#{name}.json")
  end

  def load_json(name)
    path = db_path(name)
    return nil unless File.exist?(path)
    JSON.parse(File.read(path))
  rescue
    nil
  end

  def save_json(name, data)
    File.write(db_path(name), JSON.pretty_generate(data))
  end

  def migrate_legacy
    legacy = File.join(@base_dir, "glob_data.json")
    return unless File.exist?(legacy)
    return if File.exist?(db_path("groups"))

    begin
      data = JSON.parse(File.read(legacy))
      save_json("groups",  data["groups"]  || {})
      save_json("aliases", data["aliases"] || {})
      save_json("notes",   data["notes"]   || {})
      save_json("scripts", data["scripts"] || {})

      if data["history"] && !data["history"].empty?
        data["history"].each do |entry|
          date_str = entry["time"]
          date = Date.strptime(date_str, "%Y-%m-%d %H:%M:%S") rescue Date.today
          day_key = date.strftime("%d-%m-%Y")
          path = File.join(@log_dir, "#{day_key}.json")
          entries = File.exist?(path) ? (JSON.parse(File.read(path)) rescue []) : []
          entries << entry
          File.write(path, JSON.pretty_generate(entries))
        end
      end

      FileUtils.mv(legacy, "#{legacy}.bak")
      puts "[*] Migrated glob_data.json -> db/ + logs/"
    rescue => e
      $stderr.puts "[!] Migration failed: #{e.message}"
    end
  end
end
