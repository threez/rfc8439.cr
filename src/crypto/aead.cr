class Crypto::TagException < Exception; end

# AEAD_CHACHA20_POLY1305 is an authenticated encryption with additional
# data algorithm.
class Crypto::AeadChacha20Poly1305
  # :nodoc:
  BLOCK_SIZE = 16

  # The inputs to AEAD_CHACHA20_POLY1305 are:
  # * key: A 256-bit key
  # * nonce: A 96-bit nonce -- different for each invocation with the same key
  # * io: the buffer to write the authenticated plain and ciphertext to
  def initialize(key : Bytes, nonce : Bytes, @io : IO)
    @cipher = Crypto::ChaCha20.new(key, nonce, 1)
    @mac = Crypto::Poly1305.chacha20(@cipher)
    @aad_size = 0_u64
    @plaintext_size = 0_u64
  end

  # Arbitrary length additional authenticated data (AAD).
  # Needs to be written before the plaintext. Can be called multiple
  # times, but only the last block can be less then 16 bytes.
  def aad(data : Bytes)
    @aad_size += data.size
    write(data)
  end

  # An arbitrary length plaintext, has to be multiples of 16 bytes
  # last call might be with less then 16 bytes
  def update(data : Bytes)
    @plaintext_size += data.size
    write(@cipher.encrypt(data))
  end

  # write final footer
  def final : Bytes
    footer = uninitialized UInt8[BLOCK_SIZE]
    IO::ByteFormat::LittleEndian.encode(@aad_size, footer.to_slice[0..8])
    IO::ByteFormat::LittleEndian.encode(@plaintext_size, footer.to_slice[8..15])
    write(footer.to_slice)
    @mac.final
  end

  # decrpyt parses the data and verifies the data with the tag
  # returns the additional authenticated data. The plaintext is
  # written to the provided mem, in case the tag is not validating
  # the data an exception is raised.
  def decrypt(data : Bytes, tag : Bytes) : Bytes
    # validate the tag
    @mac.update(data)
    cipher_tag = @mac.final
    if tag != cipher_tag
      raise TagException.new("mismatching tag for cipher text")
    end

    # read the footer
    footer = data[(data.size &- BLOCK_SIZE)..]
    aad_size = IO::ByteFormat::LittleEndian.decode(UInt64, footer[0..8])
    plaintext_size = IO::ByteFormat::LittleEndian.decode(UInt64, footer[8..15])

    # read the plaintext
    pad = aad_size % BLOCK_SIZE
    offset = aad_size
    offset += BLOCK_SIZE &- pad if pad != 0
    plaintext = data[offset...(offset &+ plaintext_size)]
    @io.write(@cipher.encrypt(plaintext))

    # aad
    data[0..(aad_size &- 1)]
  end

  # One-shot form of AEAD_CHACHA20_POLY1305 as specified in RFC 8439
  # section 2.8, as an alternative to the streaming/IO based instance
  # interface above. Useful whenever a protocol needs a plain
  # `encrypt(plaintext, aad) -> {ciphertext, tag}` call per message,
  # such as protecting a single TLS 1.3 record (RFC 8446 section 5.2).
  #
  # This method does not construct the per-record nonce for you: per
  # RFC 8446 section 5.3 it is the connection's fixed IV XORed with the
  # big-endian, zero left-padded 64-bit record sequence number.
  #
  # Returns the ciphertext (same length as plaintext) and the 16-byte
  # authentication tag.
  def self.encrypt(key : Bytes, nonce : Bytes, aad : Bytes, plaintext : Bytes) : {Bytes, Bytes}
    ciphertext = Crypto::ChaCha20.new(key, nonce, 1_u32).encrypt(plaintext)
    {ciphertext, mac(key, nonce, aad, ciphertext)}
  end

  # The inverse of `.encrypt`. Verifies `tag` against `aad` and
  # `ciphertext` before decrypting, raising `TagException` when it does
  # not match.
  def self.decrypt(key : Bytes, nonce : Bytes, aad : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes
    calculated_tag = mac(key, nonce, aad, ciphertext)
    if tag != calculated_tag
      raise TagException.new("mismatching tag for cipher text")
    end
    Crypto::ChaCha20.new(key, nonce, 1_u32).encrypt(ciphertext)
  end

  # :nodoc:
  # number of zero bytes needed to pad size up to the next 16 byte boundary
  private def self.pad16(size : Int) : Int
    (BLOCK_SIZE &- (size % BLOCK_SIZE)) % BLOCK_SIZE
  end

  # :nodoc:
  # computes the RFC 8439 section 2.8 authentication tag for aad/ciphertext
  # without writing either of them anywhere
  private def self.mac(key : Bytes, nonce : Bytes, aad : Bytes, ciphertext : Bytes) : Bytes
    mac = Crypto::Poly1305.chacha20(key, nonce)
    mac.update(aad)
    mac.update(Bytes.new(pad16(aad.size), 0_u8))
    mac.update(ciphertext)
    mac.update(Bytes.new(pad16(ciphertext.size), 0_u8))

    lengths = uninitialized UInt8[BLOCK_SIZE]
    IO::ByteFormat::LittleEndian.encode(aad.size.to_u64, lengths.to_slice[0, 8])
    IO::ByteFormat::LittleEndian.encode(ciphertext.size.to_u64, lengths.to_slice[8, 8])
    mac.update(lengths.to_slice)

    mac.final
  end

  private def write(data : Bytes)
    pad = data.size % BLOCK_SIZE

    if data.size >= BLOCK_SIZE
      aligned_data = data[0..(data.size &- pad &- 1)]
      @io.write(aligned_data)
      @mac.update(aligned_data)
    end

    if pad > 0
      data_with_padding = Bytes.new(BLOCK_SIZE, 0_u8)
      remainder = data[(data.size &- pad)..]
      data_with_padding.copy_from(remainder)

      @io.write(data_with_padding)
      @mac.update(data_with_padding)
    end
  end
end
