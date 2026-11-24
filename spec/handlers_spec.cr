require "./spec_helper"

# Helper to register handlers and return a fresh test client.
private def new_client
  client = ProtocolClient.new
  Handlers.register(client)
  client
end

describe "Filesystem handlers" do
  describe "fs_pwd" do
    it "returns the current working directory" do
      client = new_client
      client.inject("fs_pwd", id: "r1")

      client.sent.size.should eq(1)
      reply = client.last_sent
      reply.event.should eq("fs_reply")
      reply.id.should eq("r1")
      reply.payload.not_nil!["cwd"].as_s.should eq(Dir.current)
    end
  end

  describe "fs_cd" do
    it "changes to a valid directory" do
      client = new_client
      client.inject("fs_cd", id: "r1", payload: build_payload(path: "/tmp"))

      reply = client.last_sent
      reply.event.should eq("fs_reply")
      reply.payload.not_nil!["cwd"].as_s.should eq("/tmp")
    end

    it "stays at new directory for subsequent pwd" do
      client = new_client
      client.inject("fs_cd", id: "r1", payload: build_payload(path: "/tmp"))
      client.inject("fs_pwd", id: "r2")

      pwd_reply = client.sent.last
      pwd_reply.payload.not_nil!["cwd"].as_s.should eq("/tmp")
    end

    it "returns error for nonexistent directory" do
      client = new_client
      client.inject("fs_cd", id: "r1", payload: build_payload(path: "/nonexistent_dir_xyz"))

      reply = client.last_sent
      reply.payload.not_nil!["error"].as_s.should contain("no such directory")
    end

    it "returns error when path is missing" do
      client = new_client
      client.inject("fs_cd", id: "r1")

      reply = client.last_sent
      reply.payload.not_nil!["error"].as_s.should eq("missing path")
    end
  end

  describe "fs_ls" do
    it "lists directory contents" do
      client = new_client
      client.inject("fs_ls", id: "r1", payload: build_payload(path: "/tmp"))

      reply = client.last_sent
      reply.event.should eq("fs_reply")
      entries = reply.payload.not_nil!["entries"].as_a
      entries.should be_a(Array(JSON::Any))
    end

    it "returns error for nonexistent directory" do
      client = new_client
      client.inject("fs_ls", id: "r1", payload: build_payload(path: "/nonexistent_xyz"))

      reply = client.last_sent
      reply.payload.not_nil!["error"].as_s.should contain("no such directory")
    end
  end

  describe "fs_cat" do
    it "reads file content" do
      # Create a temp file
      tmpfile = File.tempfile("glob_test") do |f|
        f.print("hello from test")
      end

      begin
        client = new_client
        client.inject("fs_cat", id: "r1", payload: build_payload(path: tmpfile.path))

        reply = client.last_sent
        reply.event.should eq("fs_reply")
        reply.payload.not_nil!["content"].as_s.should eq("hello from test")
        reply.payload.not_nil!["size"].as_i.should eq(15)
      ensure
        tmpfile.delete
      end
    end

    it "returns error for missing file" do
      client = new_client
      client.inject("fs_cat", id: "r1", payload: build_payload(path: "/nonexistent_file.txt"))

      reply = client.last_sent
      reply.payload.not_nil!["error"].as_s.should contain("no such file")
    end

    it "returns error when path is missing" do
      client = new_client
      client.inject("fs_cat", id: "r1")

      reply = client.last_sent
      reply.payload.not_nil!["error"].as_s.should eq("missing path")
    end
  end
end

describe "Exec handler" do
  it "runs a command and returns stdout" do
    client = new_client
    client.inject("exec", id: "r1", payload: build_payload(cmd: "echo hello"))

    reply = client.last_sent
    reply.event.should eq("exec_reply")
    reply.payload.not_nil!["stdout"].as_s.strip.should eq("hello")
    reply.payload.not_nil!["exit_code"].as_i.should eq(0)
  end

  it "captures stderr" do
    client = new_client
    client.inject("exec", id: "r1", payload: build_payload(cmd: "echo err >&2"))

    reply = client.last_sent
    reply.payload.not_nil!["stderr"].as_s.strip.should eq("err")
  end

  it "returns nonzero exit code" do
    client = new_client
    client.inject("exec", id: "r1", payload: build_payload(cmd: "false"))

    reply = client.last_sent
    reply.payload.not_nil!["exit_code"].as_i.should_not eq(0)
  end

  it "returns error when cmd is missing" do
    client = new_client
    client.inject("exec", id: "r1")

    reply = client.last_sent
    reply.payload.not_nil!["error"].as_s.should eq("missing cmd")
  end
end

describe "Memfile handlers" do
  it "write and read round-trip" do
    client = new_client
    content = "#!/bin/bash\necho test"
    b64 = Base64.strict_encode(content)

    client.inject("memfile_write", id: "w1",
      payload: build_payload(name: "test.sh", data: b64))

    write_reply = client.last_sent
    write_reply.event.should eq("memfile_reply")
    write_reply.payload.not_nil!["status"].as_s.should contain("wrote")

    client.inject("memfile_read", id: "r1",
      payload: build_payload(name: "test.sh"))

    read_reply = client.last_sent
    read_reply.event.should eq("memfile_reply")
    decoded = Base64.decode_string(read_reply.payload.not_nil!["data"].as_s)
    decoded.should eq(content)
    read_reply.payload.not_nil!["size"].as_i.should eq(content.bytesize)
  end

  it "list shows stored memfiles" do
    client = new_client
    b64 = Base64.strict_encode("data")

    client.inject("memfile_write", id: "w1",
      payload: build_payload(name: "a.sh", data: b64))
    client.inject("memfile_write", id: "w2",
      payload: build_payload(name: "b.py", data: b64))
    client.inject("memfile_list", id: "l1")

    reply = client.last_sent
    files = reply.payload.not_nil!["files"].as_a
    names = files.map { |f| f["name"].as_s }
    names.should contain("a.sh")
    names.should contain("b.py")
  end

  it "delete removes a memfile" do
    client = new_client
    b64 = Base64.strict_encode("data")
    client.inject("memfile_write", id: "w1",
      payload: build_payload(name: "del.sh", data: b64))

    client.inject("memfile_delete", id: "d1",
      payload: build_payload(name: "del.sh"))
    del_reply = client.last_sent
    del_reply.payload.not_nil!["status"].as_s.should contain("deleted")

    client.inject("memfile_read", id: "r1",
      payload: build_payload(name: "del.sh"))
    read_reply = client.last_sent
    read_reply.payload.not_nil!["error"].as_s.should contain("no such memfile")
  end

  it "exec runs a script via interpreter" do
    client = new_client
    script = "echo memfile_works"
    b64 = Base64.strict_encode(script)
    client.inject("memfile_write", id: "w1",
      payload: build_payload(name: "run.sh", data: b64))

    client.inject("memfile_exec", id: "e1",
      payload: build_payload(name: "run.sh", interpreter: "bash"))

    reply = client.last_sent
    reply.event.should eq("memfile_reply")
    reply.payload.not_nil!["stdout"].as_s.strip.should eq("memfile_works")
    reply.payload.not_nil!["exit_code"].as_i.should eq(0)
  end

  it "exec returns error for missing memfile" do
    client = new_client
    client.inject("memfile_exec", id: "e1",
      payload: build_payload(name: "nope.sh"))

    reply = client.last_sent
    reply.payload.not_nil!["error"].as_s.should contain("no such memfile")
  end
end

describe "Shell handlers" do
  it "opens a shell and receives shell_ready" do
    client = new_client
    client.inject("shell_open", id: "s1")

    # Should get shell_ready
    ready = client.sent.find { |e| e.event == "shell_ready" }
    ready.should_not be_nil
    ready.not_nil!.id.should eq("s1")
    ready.not_nil!.payload.not_nil!["status"].as_s.should eq("ok")

    # Clean up
    client.inject("shell_close", id: "s1")
    sleep 100.milliseconds
  end

  it "receives output after sending data" do
    client = new_client
    client.inject("shell_open", id: "s2")
    sleep 200.milliseconds
    client.clear!

    client.inject("shell_data", id: "s2",
      payload: build_payload(data: "echo shell_test_output\n"))
    sleep 500.milliseconds

    outputs = client.sent.select { |e| e.event == "shell_output" && e.id == "s2" }
    combined = outputs.map { |e|
      b64 = e.payload.not_nil!["data"].as_s
      Base64.decode_string(b64)
    }.join

    combined.should contain("shell_test_output")

    client.inject("shell_close", id: "s2")
    sleep 100.milliseconds
  end

  it "closes shell cleanly" do
    client = new_client
    client.inject("shell_open", id: "s3")
    sleep 200.milliseconds

    # Send exit command so bash terminates, triggering shell_closed from the read fiber
    client.inject("shell_data", id: "s3",
      payload: build_payload(data: "exit\n"))

    # Wait for the process to actually exit and send shell_closed
    20.times do
      break if client.sent.any? { |e| e.event == "shell_closed" && e.id == "s3" }
      sleep 200.milliseconds
    end

    closed = client.sent.find { |e| e.event == "shell_closed" && e.id == "s3" }
    closed.should_not be_nil
  end
end

describe "Sysadmin handlers" do
  describe "sys_ps" do
    it "returns process list" do
      client = new_client
      client.inject("sys_ps", id: "r1")

      reply = client.last_sent
      reply.event.should eq("sys_reply")
      procs = reply.payload.not_nil!["processes"].as_a
      procs.size.should be > 0
      procs.first["pid"].as_i.should be > 0
    end

    it "filters by keyword" do
      client = new_client
      payload = build_payload(filter: "crystal")
      client.inject("sys_ps", id: "r1", payload: payload)

      reply = client.last_sent
      procs = reply.payload.not_nil!["processes"].as_a
      procs.each do |pr|
        (pr["command"].as_s.downcase.includes?("crystal") ||
         pr["user"].as_s.downcase.includes?("crystal")).should be_true
      end
    end
  end

  describe "sys_top" do
    it "returns system metrics" do
      client = new_client
      client.inject("sys_top", id: "r1")

      reply = client.last_sent
      reply.event.should eq("sys_reply")
      p = reply.payload.not_nil!
      p["cpu_percent"].as_f.should be >= 0.0
      p["cpu_count"].as_i.should be > 0
      p["mem_total"].as_i64.should be > 0
      p["mem_used"].as_i64.should be >= 0
    end
  end
end

describe "Find handler" do
  it "searches current directory" do
    client = new_client
    client.inject("find_files", id: "r1",
      payload: build_payload(name: "*.cr", maxdepth: 1))

    reply = client.last_sent
    reply.event.should eq("find_reply")
    files = reply.payload.not_nil!["files"].as_a
    files.should be_a(Array(JSON::Any))
  end

  it "searches with type filter" do
    client = new_client
    client.inject("find_files", id: "r1",
      payload: build_payload(path: "/tmp", type: "d", maxdepth: 1))

    reply = client.last_sent
    reply.event.should eq("find_reply")
    reply.payload.not_nil!["files"].as_a.should be_a(Array(JSON::Any))
  end

  it "searches without arguments (cwd)" do
    client = new_client
    client.inject("find_files", id: "r1")

    reply = client.last_sent
    reply.event.should eq("find_reply")
    reply.payload.not_nil!["files"].as_a.size.should be > 0
  end
end

describe "Package handler" do
  it "returns error for missing action" do
    client = new_client
    client.inject("pkg_action", id: "r1",
      payload: build_payload(foo: "bar"))

    reply = client.last_sent
    reply.event.should eq("pkg_reply")
    reply.payload.not_nil!["error"].as_s.should contain("missing action")
  end

  it "returns error for missing package name" do
    client = new_client
    client.inject("pkg_action", id: "r1",
      payload: build_payload(action: "install"))

    reply = client.last_sent
    reply.event.should eq("pkg_reply")
    reply.payload.not_nil!["error"].as_s.should contain("missing package name")
  end

  it "lists installed packages" do
    client = new_client
    client.inject("pkg_action", id: "r1",
      payload: build_payload(action: "list"))

    reply = client.last_sent
    reply.event.should eq("pkg_reply")
    p = reply.payload.not_nil!
    p["manager"].as_s.should_not be_empty
    p["exit_code"]?.should_not be_nil
  end
end

describe "Network handlers" do
  describe "net_ifconfig" do
    it "returns network interfaces" do
      client = new_client
      client.inject("net_ifconfig", id: "r1")

      reply = client.last_sent
      reply.event.should eq("net_reply")
      ifaces = reply.payload.not_nil!["interfaces"]
      ifaces.as_h.size.should be > 0
      ifaces.as_h.has_key?("lo").should be_true
    end
  end

  describe "net_netstat" do
    it "returns listening sockets" do
      client = new_client
      client.inject("net_netstat", id: "r1",
        payload: build_payload(mode: "listening"))

      reply = client.last_sent
      reply.event.should eq("net_reply")
      reply.payload.not_nil!["mode"].as_s.should eq("listening")
      reply.payload.not_nil!["sockets"].as_a.should be_a(Array(JSON::Any))
    end
  end
end
