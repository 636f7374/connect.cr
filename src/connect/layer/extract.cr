module CONNECT::Layer
  class Extract < IO
    getter partMemory : IO::Memory
    getter wrapped : IO

    def initialize(@partMemory : IO::Memory, @wrapped : IO)
    end

    private def eof? : Bool
      partMemory.pos == partMemory.size
    end

    def write(slice : Bytes) : Nil
      raise Exception.new "CONNECT::Layer::Extract.write: Read-only IO, not writable!"
    end

    def read(slice : Bytes) : Int32
      return wrapped.read slice if partMemory.closed?

      length = partMemory.read slice
      partMemory.close if eof?

      length
    end

    def close
      wrapped.close
    end
  end
end
