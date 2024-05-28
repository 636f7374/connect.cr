module CONNECT::Layer
  class BufferReader < IO
    getter wrapped : IO
    getter memory : IO::Memory

    def initialize(@wrapped : IO)
      @memory = IO::Memory.new
    end

    def write(slice : Bytes) : Nil
      raise Exception.new "CONNECT::Layer::Buffer.write: Read-only IO, not writable!"
    end

    def read(slice : Bytes) : Int32
      length = wrapped.read slice: slice
      memory.write slice: slice[0_i32, length]

      length
    end

    def close
      wrapped.close
    end
  end
end
