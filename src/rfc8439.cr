require "./crypto/number"
require "./crypto/text"
require "./crypto/chacha20"

module Rfc8439
  VERSION = "0.1.0"
end

module Crypto
  def self.only_hex(input : String) : String
    input.gsub(/[^a-fA-F0-9]/, "")
  end
end
