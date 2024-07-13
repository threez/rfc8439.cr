module Crypto::Hex
  def self.bytes(input : String) : Bytes
    input.gsub(/[^a-fA-F0-9]/, "").hexbytes
  end
end
