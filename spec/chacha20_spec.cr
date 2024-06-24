require "./spec_helper"

describe Crypto::ChaCha20 do
  it "2.3.2.  Test Vector for the ChaCha20 Block Function" do
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    nonce = "00:00:00:09:00:00:00:4a:00:00:00:00"
    chipher = Crypto::ChaCha20.new(key, nonce, 1)

    chipher.next_key_block
    chipher.to_hex.should eq(Crypto.only_hex("
      e4e7f110  15593bd1  1fdd0f50  c47120a3
      c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
      466482d2  09aa9f07  05d7c214  a2028bd9
      d19c12b5  b94e16de  e883d0cb  4e3c50a2
    "))
  end

  it "2.4.2.  Example and Test Vector for the ChaCha20 Cipher" do
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    nonce = "00:00:00:00:00:00:00:4a:00:00:00:00"
    chipher = Crypto::ChaCha20.new(key, nonce, 1)

    result = chipher.encrypt(Crypto::Text.new("
      4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
      65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
      73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
      6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
      6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
      74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
      63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
      74 2e
    "))

    result.to_hex.should eq(Crypto::Text.new("
      6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
      e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
      f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
      16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
      07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
      52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
      5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
      87 4d
    ").to_hex)

    # chipher = Crypto::ChaCha20.new(key, nonce, 1)
    # result = chipher.encrypt("Ladies and Gentlemen of the class of '99: If I could offer you only one tip forthe future, sunscreen would be it.")
    # result.to_hex.should eq(Crypto::Text.new("
    #   6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
    #   e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
    #   f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
    #   16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
    #   07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
    #   52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
    #   5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
    #   87 4d
    # ").to_hex)
  end

  describe "A.1.  The ChaCha20 Block Functions" do
    it "Test Vector #1" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
      chipher = Crypto::ChaCha20.new(key, nonce, 0)

      chipher.next_key_block
      chipher.to_hex.should eq(Crypto.only_hex("
        ade0b876  903df1a0  e56a5d40  28bd8653
        b819d2bd  1aed8da0  ccef36a8  c70d778b
        7c5941da  8d485751  3fe02477  374ad8b8
        f4b8436a  1ca11815  69b687c3  8665eeb2
      "))
    end

    it "Test Vector #2" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
      chipher = Crypto::ChaCha20.new(key, nonce, 1)

      chipher.next_key_block
      chipher.to_hex.should eq(Crypto.only_hex("
        bee7079f  7a385155  7c97ba98  0d082d73
        a0290fcb  6965e348  3e53c612  ed7aee32
        7621b729  434ee69c  b03371d5  d539d874
        281fed31  45fb0a51  1f0ae1ac  6f4d794b
      "))
    end

    it "Test Vector #3" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
      chipher = Crypto::ChaCha20.new(key, nonce, 1)

      chipher.next_key_block
      chipher.to_hex.should eq(Crypto.only_hex("
        2452eb3a  9249f8ec  8d829d9b  ddd4ceb1
        e8252083  60818b01  f38422b8  5aaa49c9
        bb00ca8e  da3ba7b4  c4b592d1  fdf2732f
        4436274e  2561b3c8  ebdd4aa6  a0136c00
      "))
    end

    it "Test Vector #4" do
      key = "00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
      chipher = Crypto::ChaCha20.new(key, nonce, 2)

      chipher.next_key_block
      chipher.to_hex.should eq(Crypto.only_hex("
        fb4dd572  4bc42ef1  df922636  327f1394
        a78dea8f  5e269039  a1bebbc1  caf09aae
        a25ab213  48a6b46c  1b9d9bcb  092c5be6
        546ca624  1bec45d5  87f47473  96f0992e
      "))
    end

    it "Test Vector #5" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
      chipher = Crypto::ChaCha20.new(key, nonce, 0)

      chipher.next_key_block
      chipher.to_hex.should eq(Crypto.only_hex("
        374dc6c2  3736d58c  b904e24a  cd3f93ef
        88228b1a  96a4dfb3  5b76ab72  c727ee54
        0e0e978a  f3145c95  1b748ea8  f786c297
        99c28f5f  628314e8  398a19fa  6ded1b53
      "))
    end
  end

  describe "A.2.  ChaCha20 Encryption" do
    it "Test Vector #1" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
      chipher = Crypto::ChaCha20.new(key, nonce, 0)

      result = chipher.encrypt(Crypto::Text.new("
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      "))

      result.to_hex.should eq(Crypto::Text.new("
        76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
        bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
        da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
        6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
      ").to_hex)
    end

    it "Test Vector #2" do
      key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
      chipher = Crypto::ChaCha20.new(key, nonce, 1)

      result = chipher.encrypt(Crypto::Text.new("
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
      "))

      result.to_hex.should eq(Crypto::Text.new("
        a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
        41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
        2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
        0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
        40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
        20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
        42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
        68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
        d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
        42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
        c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
        e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
        08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
        a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
        cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
        a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
        c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
        8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
        58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
        be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
        98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
        14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
        7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
        c4 fd 80 6c 22 f2 21
      ").to_hex)
    end

    it "Test Vector #3" do
      key = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
      nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
      chipher = Crypto::ChaCha20.new(key, nonce, 42)

      result = chipher.encrypt(Crypto::Text.new("
        27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
        6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
        76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
        20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
        61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
        65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
        73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
        72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
      "))

      result.to_hex.should eq(Crypto::Text.new("
        62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df
        5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf
        16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71
        fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb
        f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6
        1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77
        04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1
        87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
      ").to_hex)
    end
  end
end
