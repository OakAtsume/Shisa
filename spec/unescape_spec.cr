require "./spec_helper"

describe "Handlers.unescape_strace" do
  it "decodes hex escapes" do
    result = Handlers.unescape_strace("\\x48\\x65\\x6c\\x6c\\x6f")
    String.new(result).should eq("Hello")
  end

  it "decodes standard C escapes" do
    result = Handlers.unescape_strace("\\n\\r\\t")
    result.should eq(Bytes[0x0A, 0x0D, 0x09])
  end

  it "decodes alert, backspace, formfeed, vtab" do
    result = Handlers.unescape_strace("\\a\\b\\f\\v")
    result.should eq(Bytes[0x07, 0x08, 0x0C, 0x0B])
  end

  it "decodes escaped backslash and quote" do
    result = Handlers.unescape_strace("\\\\\\\"")
    result.should eq(Bytes[0x5C, 0x22])
  end

  it "decodes octal escapes" do
    result = Handlers.unescape_strace("\\101\\102\\103")
    String.new(result).should eq("ABC")
  end

  it "handles mixed content" do
    result = Handlers.unescape_strace("\\x48i\\n")
    String.new(result).should eq("Hi\n")
  end

  it "passes through plain ASCII" do
    result = Handlers.unescape_strace("hello world")
    String.new(result).should eq("hello world")
  end

  it "handles empty input" do
    result = Handlers.unescape_strace("")
    result.size.should eq(0)
  end

  it "decodes null byte" do
    result = Handlers.unescape_strace("\\x00")
    result.should eq(Bytes[0x00])
  end

  it "decodes high bytes (>127)" do
    result = Handlers.unescape_strace("\\xff\\x80")
    result.should eq(Bytes[0xFF, 0x80])
  end
end
