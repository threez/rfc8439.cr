require "./crypto/chacha20"

module Rfc8439
  VERSION = "0.1.0"
end

module Crypto
  def self.only_hex(input : String) : String
    input.gsub(/[^a-fA-F0-9]/, "")
  end

  def self.to_hex(block : WordBlock) : String
    str = ""
    16.times do |i|
      str += block[i].to_s(16).rjust(8, '0')
    end
    str
  end

  def self.to_hex(raw : Bytes) : String
    str = ""
    raw.each do |byte|
      str += byte.to_s(16).rjust(2, '0')
    end
    str
  end

  def self.parse_hex(input : String) : Bytes
    hex_str = Crypto.only_hex(input)
    bytes = hex_str.hexbytes
    Bytes.new(bytes.size) { |i| bytes[i] }
  end
end
