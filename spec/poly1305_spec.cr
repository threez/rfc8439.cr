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

  describe "A.3.  Poly1305 Message Authentication Code" do
    it "Test Vector #1" do
      key = Crypto::Hex.bytes("
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end

    it "Test Vector #2" do
      key = Crypto::Hex.bytes("
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e
      ")
      msg = Crypto::Hex.bytes("
        41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
        6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
        64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
        69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
        63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
        20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
        20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
        6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
        74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
        74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
        20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
        76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
        65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
        72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
        73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
        64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
        74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
        6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
        77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
        74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
        74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
        79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
        20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
        73 73 65 64 20 74 6f
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"))
    end

    it "Test Vector #3" do
      key = Crypto::Hex.bytes("
        36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
        6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
        64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
        69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
        63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
        20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
        20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
        6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
        74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
        74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
        20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
        76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
        65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
        72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
        73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
        64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
        74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
        6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
        77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
        74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
        74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
        79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
        20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
        73 73 65 64 20 74 6f
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0"))
    end

    it "Test Vector #4" do
      key = Crypto::Hex.bytes("
        1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
        47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
      ")
      msg = Crypto::Hex.bytes("
        27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
        6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
        76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
        20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
        61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
        65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
        73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
        72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62"))
    end

    it "Test Vector #5" do
      key = Crypto::Hex.bytes("
        02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end

    it "Test Vector #6" do
      key = Crypto::Hex.bytes("
        02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
      ")
      msg = Crypto::Hex.bytes("
        02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end

    it "Test Vector #7" do
      key = Crypto::Hex.bytes("
        01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end

    it "Test Vector #8" do
      key = Crypto::Hex.bytes("
        01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
        01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end

    it "Test Vector #9" do
      key = Crypto::Hex.bytes("
        02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"))
    end

    it "Test Vector #10" do
      key = Crypto::Hex.bytes("
        01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
        33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00"))
    end

    it "Test Vector #11" do
      key = Crypto::Hex.bytes("
        01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      msg = Crypto::Hex.bytes("
        E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
        33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ")
      mac = Crypto::Poly1305.new(key)
      mac.update(msg)
      tag = mac.final
      to_hex(tag).should eq(only_hex("13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))
    end
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

    describe "A.4.  Poly1305 Key Generation Using ChaCha20" do
      it "Test Vector #1" do
        key = Crypto::Hex.bytes("
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        ")
        nonce = Crypto::Hex.bytes("
          00 00 00 00 00 00 00 00 00 00 00 00
        ")
        mac = Crypto::Poly1305.chacha20(key, nonce)
        to_hex(mac.key).should eq(only_hex("
          76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
          bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
        "))
      end

      it "Test Vector #2" do
        key = Crypto::Hex.bytes("
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
        ")
        nonce = Crypto::Hex.bytes("
          00 00 00 00 00 00 00 00 00 00 00 02
        ")
        mac = Crypto::Poly1305.chacha20(key, nonce)
        to_hex(mac.key).should eq(only_hex("
          ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76
          06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39
        "))
      end

      it "Test Vector #3" do
        key = Crypto::Hex.bytes("
          1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
          47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
        ")
        nonce = Crypto::Hex.bytes("
          00 00 00 00 00 00 00 00 00 00 00 02
        ")
        mac = Crypto::Poly1305.chacha20(key, nonce)
        to_hex(mac.key).should eq(only_hex("
          96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b
          13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae
        "))
      end
    end
  end
end
