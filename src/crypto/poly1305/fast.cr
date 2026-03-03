require "../chacha20"

# Poly1305 message authentication code (pure Crystal limb-arithmetic backend).
#
# Uses 3×44-bit limbs in UInt64 with UInt128 intermediate products,
# following the poly1305-donna algorithm. Avoids heap-allocated BigInt
# entirely.
class Crypto::Poly1305::Fast < Crypto::Poly1305::MAC
  # :nodoc:
  BLOCK_SIZE = 16
  # :nodoc:
  CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff_u128
  # :nodoc:
  MASK44 = (1_u64 << 44) &- 1
  # :nodoc:
  MASK42 = (1_u64 << 42) &- 1

  # r limbs
  @r0 : UInt64
  @r1 : UInt64
  @r2 : UInt64

  # pre-computed r * 20 (for cross-term reduction with 44-bit limbs)
  @s1 : UInt64
  @s2 : UInt64

  # accumulator limbs
  @h0 : UInt64
  @h1 : UInt64
  @h2 : UInt64

  # second half of key (pad)
  @pad : UInt128

  getter key : Bytes

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(key : Bytes, nonce : Bytes) : self
    chacha20(Crypto::ChaCha20.new(key, nonce))
  end

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(cipher : ChaCha20::Cipher) : self
    block = Crypto::ChaCha20.block_bytes(cipher.clone.next_key_block, false)
    new(block[0..31])
  end

  # Initializes the Poly1305 context with a given 32-byte key.
  def initialize(@key : Bytes)
    raise "key needs to be 256 bits (32 bytes)" if @key.size != 32

    # Decode r as UInt128 LE, clamp
    r = IO::ByteFormat::LittleEndian.decode(UInt128, @key[0, 16])
    r &= CLAMP

    # Split r into 3×44-bit limbs
    @r0 = (r & MASK44).to_u64!
    @r1 = ((r >> 44) & MASK44).to_u64!
    @r2 = ((r >> 88) & MASK42).to_u64!

    # Pre-compute: for 44-bit limbs, cross-terms at 2^132 = 4·2^130 ≡ 4·5 = 20 (mod p)
    @s1 = @r1 &* 20_u64
    @s2 = @r2 &* 20_u64

    # Accumulator starts at zero
    @h0 = 0_u64
    @h1 = 0_u64
    @h2 = 0_u64

    # Decode pad (second 16 bytes of key)
    @pad = IO::ByteFormat::LittleEndian.decode(UInt128, @key[16, 16])
  end

  # Initializes the Poly1305 context with a given 32-byte **hex-encoded** key.
  def initialize(key : String)
    initialize(Crypto::Hex.bytes(key))
  end

  # Processes a message fragment.
  def update(msg : Bytes)
    offset = 0
    remaining = msg.size

    # Process full 16-byte blocks
    while remaining >= BLOCK_SIZE
      n = IO::ByteFormat::LittleEndian.decode(UInt128, msg[offset, BLOCK_SIZE])

      # Split block into limbs and add hibit (1 << 128 → bit 40 of limb 2)
      @h0 &+= (n & MASK44).to_u64!
      @h1 &+= ((n >> 44) & MASK44).to_u64!
      @h2 &+= ((n >> 88).to_u64! & MASK42) | (1_u64 << 40)

      multiply_reduce

      offset &+= BLOCK_SIZE
      remaining &-= BLOCK_SIZE
    end

    # Process partial final block
    if remaining > 0
      # Zero-pad to 16 bytes, then add sentinel byte at position remaining
      buf = Bytes.new(BLOCK_SIZE, 0_u8)
      msg[offset, remaining].copy_to(buf.to_slice)
      n = IO::ByteFormat::LittleEndian.decode(UInt128, buf)
      # Add sentinel: 0x01 at bit position remaining*8
      n |= 1_u128 << (remaining &* 8)

      @h0 &+= (n & MASK44).to_u64!
      @h1 &+= ((n >> 44) & MASK44).to_u64!
      @h2 &+= (n >> 88).to_u64! & MASK42

      multiply_reduce
    end
  end

  # Finalizes the MAC computation and returns the 16-byte authenticator.
  def final : Bytes
    h0 = @h0
    h1 = @h1
    h2 = @h2

    # Full carry chain to normalize limbs
    c = h0 >> 44; h0 &= MASK44
    h1 &+= c; c = h1 >> 44; h1 &= MASK44
    h2 &+= c; c = h2 >> 42; h2 &= MASK42
    h0 &+= c &* 5; c = h0 >> 44; h0 &= MASK44
    h1 &+= c

    # Constant-time conditional subtraction of p = 2^130 - 5
    # Compute g = h - p = h + 5 - 2^130
    g0 = h0 &+ 5; c = g0 >> 44; g0 &= MASK44
    g1 = h1 &+ c; c = g1 >> 44; g1 &= MASK44
    g2 = h2 &+ c &- (1_u64 << 42)

    # If g2 bit 63 is set (negative / underflow), h < p → keep h; otherwise use g
    mask = (g2 >> 63) &- 1 # 0 if g2 negative (keep h), all-ones if g >= 0 (use g)
    g0 &= mask
    g1 &= mask
    g2 &= mask
    mask = ~mask
    h0 = (h0 & mask) | g0
    h1 = (h1 & mask) | g1
    h2 = (h2 & mask) | g2

    # Reassemble as UInt128 and add pad
    h = h0.to_u128! | (h1.to_u128! << 44) | (h2.to_u128! << 88)
    h &+= @pad

    # Encode lower 128 bits as LE
    tag = Bytes.new(BLOCK_SIZE)
    IO::ByteFormat::LittleEndian.encode(h.to_u128!, tag)
    tag
  end

  # A convenience method to compute a Poly1305 MAC for a single message.
  def self.auth(key : Bytes, message : Bytes) : Bytes
    pa = new(key)
    pa.update(message)
    pa.final
  end

  @[AlwaysInline]
  private def multiply_reduce
    h0 = @h0.to_u128!
    h1 = @h1.to_u128!
    h2 = @h2.to_u128!
    r0 = @r0.to_u128!
    r1 = @r1.to_u128!
    r2 = @r2.to_u128!
    s1 = @s1.to_u128!
    s2 = @s2.to_u128!

    # Schoolbook multiplication with reduction
    d0 = h0 &* r0 &+ h1 &* s2 &+ h2 &* s1
    d1 = h0 &* r1 &+ h1 &* r0 &+ h2 &* s2
    d2 = h0 &* r2 &+ h1 &* r1 &+ h2 &* r0

    # Carry propagation
    c = d0 >> 44; @h0 = d0.to_u64! & MASK44
    d1 &+= c; c = d1 >> 44; @h1 = d1.to_u64! & MASK44
    d2 &+= c; c = d2 >> 42; @h2 = d2.to_u64! & MASK42

    # Top carry × 5 feeds back into h0 (since 2^130 ≡ 5 mod p)
    @h0 &+= c.to_u64! &* 5
    c = @h0.to_u128! >> 44; @h0 &= MASK44
    @h1 &+= c.to_u64!
  end
end
