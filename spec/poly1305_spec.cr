require "./spec_helper"

describe Crypto::Poly1305 do
  it "2.5.2.  Poly1305 Example and Test Vector" do
    key = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
    msg = "
      43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f
      72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f
      75 70
    "
    mac = Crypto::Poly1305.new(key)
    mac.update(Crypto::Hex.bytes(msg))
    tag = mac.final
    to_hex(tag).should eq(only_hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9"))
  end

  describe "#auth" do
    it "should work" do
      key = Crypto::Hex.bytes("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b")
      msg = "Cryptographic Forum Research Group".to_slice

      tag = Crypto::Poly1305.auth(key, msg)
      to_hex(tag).should eq(only_hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9"))
    end
  end

  describe "#update" do
    it "can be called multiple times" do
      key = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
      mac = Crypto::Poly1305.new(key)
      mac.update(Crypto::Hex.bytes("43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f"))
      mac.update(Crypto::Hex.bytes("72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f"))
      mac.update(Crypto::Hex.bytes("75 70"))
      tag = mac.final
      to_hex(tag).should eq(only_hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9"))
    end
  end

  describe "example" do
    it "should work" do
      key = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
      msg = "Cryptographic Forum Research Group".to_slice

      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9"))
    end
  end

  describe ".chacha20" do
    it "should generate a poly1305 based of a chacha20 key and nonce" do
      key = Crypto::Hex.bytes("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f")
      nonce = Crypto::Hex.bytes("00 00 00 00 00 01 02 03 04 05 06 07")
      mac = Crypto::Poly1305.chacha20(key, nonce)
      msg = "Cryptographic Forum Research Group".to_slice
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("92:65:cf:2a:a8:f4:4c:e9:bd:db:92:2b:3d:65:0e:7c"))
    end
  end
end
