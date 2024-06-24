module Crypto
  class Text
    getter raw : Array(UInt8) | Bytes
    property fill : Int32 = 0

    delegate :[], to: @raw
    delegate :[]=, to: @raw
    delegate :size, to: @raw

    def initialize(size : Number)
      @raw = Array(UInt8).new(size)
    end

    def initialize(input : String)
      hex_str = Crypto.only_hex(input)
      bytes = hex_str.hexbytes
      @raw = Array(UInt8).new(bytes.size) do |i|
        bytes[i]
      end
    end

    def initialize(@raw : Array(UInt8) | Bytes)
    end

    def each_block(block_size : Number, &)
      (size // block_size).times do |pos|
        yield(Text.new(@raw[pos*block_size, block_size]))
      end

      if @raw.size % 64 != 0
        pos = (@raw.size // 64) * 64
        fill = (@raw.size - pos) % 64
        last_block = Text.new(@raw[pos, @raw.size])
        fill.times { last_block << 0_u8 }
        last_block.fill = fill
        yield(last_block)
      end
    end

    def xor(other : Text | Array(UInt8))
      @raw.size.times { |i| @raw[i] ^= other[i] }
    end

    def xor(other : Array(UInt32))
      other.each_with_index do |val, i|
        @raw[i*4] ^= (val >> 0 * 8) & 0xff_u8
        @raw[i*4 + 1] ^= (val >> 1 * 8) & 0xff_u8
        @raw[i*4 + 2] ^= (val >> 2 * 8) & 0xff_u8
        @raw[i*4 + 3] ^= (val >> 3 * 8) & 0xff_u8
      end
    end

    def <<(other : Text)
      raw = @raw.to_a
      other.raw[0, other.size - other.fill].each do |byte|
        raw << byte
      end
      @raw = raw
    end

    def <<(other : UInt8)
      raw = @raw.to_a
      raw << other
      @raw = raw
    end

    def to_hex : String
      str = ""
      @raw.each do |byte|
        str += byte.to_s(16).rjust(2, '0')
      end
      str
    end
  end
end
